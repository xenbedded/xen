/*
 * NVIDIA Tegra specific settings
 *
 * Ian Campbell; Copyright (c) 2014 Citrix Systems
 * Kyle Temkin; Copyright (c) 2016 Assured Information Security, Inc.
 * Chris Patterson; Copyright (c) 2016 Assured Information Security, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <xen/config.h>
#include <xen/lib.h>
#include <xen/stdbool.h>
#include <xen/sched.h>
#include <xen/vmap.h>

#include <asm/io.h>
#include <asm/gic.h>
#include <asm/platform.h>
#include <asm/platforms/tegra.h>


/* Permanent mapping to the Tegra legacy interrupt controller. */
static void __iomem *tegra_ictlr_base = NULL;

/*
 * List of legacy interrupt controllers that can be used to route
 * Tegra interrupts.
 */
static const char * const tegra_interrupt_compat[] __initconst =
{
    "nvidia,tegra120-ictlr",  /* Tegra K1 controllers */
    "nvidia,tegra210-ictlr"   /* Tegra X1 controllers */
};


/**
 * Returns true if the given IRQ belongs to a supported tegra interrupt
 * controller.
 *
 * @param rirq The raw IRQ to be identified.
 * @return True iff the given IRQ belongs to a Tegra ictlr.
 */
static bool_t tegra_irq_belongs_to_ictlr(struct dt_raw_irq * rirq)  {
    int i;

    for (i = 0; i < ARRAY_SIZE(tegra_interrupt_compat); i++)
    {
        if ( dt_device_is_compatible(rirq->controller, tegra_interrupt_compat[i]) )
            return true;
    }

    return false;
}


/**
 * Returns true iff the given IRQ is routable -- that is, if it is descended
 * from the platform's primary GIC.
 *
 * @param rirq The raw IRQ in question.
 * @return True iff the given IRQ routes to a platform GIC.
 */
static bool_t tegra_irq_is_routable(struct dt_raw_irq * rirq)
{
    /* If the IRQ connects directly to our GIC, it's trivially routable. */
    if ( rirq->controller == dt_interrupt_controller )
        return true;

    /*
     * If the IRQ belongs to a legacy interrupt controller, then it's
     * effectively owned by the GIC, and is routable.
     */
    if ( tegra_irq_belongs_to_ictlr(rirq) )
        return true;

    return false;
}

/**
 * Returns the IRQ number for a given device. Tegra IRQs transalate using the
 * same algorithm as normal GIC IRQs, but aren't parented by the system GIC.
 *
 * As a result, translation fails an assertion in the normal translation path.
 * The normal version is essentially dt_irq_xlate wrapped with an assert, so
 * we'll just call dt_irq_xlate directly.
 *
 * @param device The DT node describing the device.
 * @param index The index of the interrupt within the device node.
 * @return The translated number of the IRQ, or a negative error code.
 */
static int tegra_irq_for_device(const struct dt_device_node *device, int index)
{
    struct dt_raw_irq raw;
    struct dt_irq dt_irq;
    int res;

    res = dt_device_get_raw_irq(device, index, &raw);
    if ( res )
        return -ENODEV;

    /*
     * The translation function for the Tegra ictlr happens to match the
     * translation function for the normal GIC, so we'll use that in either
     * case.
     */
    res = dt_irq_xlate(raw.specifier, raw.size, &dt_irq.irq, &dt_irq.type);
    if ( res )
        return -ENODEV;

    if ( irq_set_type(dt_irq.irq, dt_irq.type) )
        return -ENODEV;

    return dt_irq.irq;
}

/**
 * Platform-specific reset code for the Tegra devices.
 * Should not return.
 */
static void tegra_reset(void)
{
    void __iomem *addr;
    u32 val;

    addr = ioremap_nocache(TEGRA_RESET_BASE, TEGRA_RESET_SIZE);
    if ( !addr )
    {
        printk(XENLOG_ERR "Tegra: Unable to map tegra reset address. Reset failed!\n");
        return;
    }

    /* Write into the reset device. */
    val = readl(addr) | TEGRA_RESET_MASK;
    writel(val, addr);

    iounmap(addr);
}

/**
 * Applies an interrupt enable to a given interrupt via the legacy
 * interrupt controller, and marks that interrupt as a normal interrupt,
 * rather than a fast IRQ.
 *
 * @param irq The hardware IRQ number for the given interrupt.
 */
static void tegra_ictlr_set_interrupt_enable(unsigned int irq, bool enabled)
{
    uint32_t previous_iep_class;

    /* If we're enabling a given bit, use the SET register; otherwise CLR. */
    unsigned int register_number =
        enabled ? TEGRA_ICTLR_CPU_IER_SET : TEGRA_ICTLR_CPU_IER_CLR;

    /*
     * Determine the IRQ number in the ictlr domain, and figure out the indexA
     * of the individual controller we're working with. */
    unsigned int ictlr_irq = irq - NR_LOCAL_IRQS;
    unsigned int ictlr_number = ictlr_irq / TEGRA_IRQS_PER_ICTLR;

    /* Get a pointer to the target ictlr. */
    void __iomem * target_ictlr = tegra_ictlr_base + TEGRA_ICTLR_SIZE * ictlr_number;

    /* Determine the mask we'll be working with. */
    uint32_t mask = BIT(ictlr_irq % TEGRA_IRQS_PER_ICTLR);

    /* Sanity check our memory access. */
    ASSERT(tegra_ictlr_base);
    ASSERT(ictlr_number < TEGRA_ICTLR_COUNT);
    ASSERT(irq >= NR_LOCAL_IRQS);

    /* Enable the given IRQ. */
    writel(mask, target_ictlr + register_number);

    /* Mark the interrupt as a normal interrupt-- not a fast IRQ. */
    previous_iep_class = readl(target_ictlr + TEGRA_ICTLR_CPU_IEP_CLASS);
    writel(previous_iep_class & ~mask, target_ictlr + TEGRA_ICTLR_CPU_IEP_CLASS);
}


/**
 * Routes an IRQ to a guest, applying sane values to the ictlr masks.
 *
 * @param domain The domain to which the IRQ will be routed.
 * @param virq The virtual IRQ number.
 * @param desc The IRQ to be routed.
 * @param priority The IRQ priority.
 * @return 0 on success, or an error code on failure.
 */
static int tegra_route_irq_to_guest(struct domain *d, unsigned int virq,
                                struct irq_desc *desc, unsigned int priority)
{
    /* Program the core GIC to deliver the interrupt to the guest. */
    int rc = gic_route_irq_to_guest(d, virq, desc, priority);

    /* If we couldn't route the IRQ via the GIC, bail out. */
    if(rc)
    {
        printk(XENLOG_ERR "Tegra LIC: Couldn't program GIC to route vIRQ %d (%d).\n",
               desc->irq, rc);
        return rc;
    }

    /*
     * If this is a local IRQ, it's not masked by the ictlr, so we
     * don't need to perform any ictlr manipulation.
     */
    if( desc->irq < NR_LOCAL_IRQS )
        return rc;

    /*
     * If this is the hardware domain, it will have real access to the ictlr,
     * and will program the ictlr itself, so it should start with the ictlr
     * disabled. If we're not the hwdom, the domain won't interact with the
     * ictlr, and the interrupt shouldn't be masked.
     */
    tegra_ictlr_set_interrupt_enable(desc->irq, !is_hardware_domain(d));
    return rc;
}


/**
 * Routes an IRQ to Xen. This method both performs the core IRQ routing, and
 * sets up any ictlr routing necessary.
 *
 * @param desc The IRQ to be routed.
 * @param priority The IRQ priority.
 */
static void tegra_route_irq_to_xen(struct irq_desc *desc, unsigned int priority)
{
    unsigned int irq = desc->irq;

    /* Program the core GIC to deliver the interrupt to Xen. */
    gic_route_irq_to_xen(desc, priority);

    /*
     * If this is a local IRQ, it's not masked by the ictlr, so we
     * don't need to perform any ictlr manipulation.
     */
    if( irq < NR_LOCAL_IRQS )
        return;

    /*
     * Enable the interrupt in the ictlr. Xen only uses the GIC to
     * perform masking, so we'll enable the interrupt to prevent ictlr
     * gating of the interrupt.
     */
    tegra_ictlr_set_interrupt_enable(irq, true);

}

/**
 * Initialize the Tegra legacy interrupt controller, placing each interrupt
 * into a default state. These defaults ensure that stray interrupts don't
 * affect Xen.
 */
static int tegra_initialize_legacy_interrupt_controller(void)
{
    int i;

    /* Map in the tegra ictlr. */
    tegra_ictlr_base = ioremap_nocache(TEGRA_ICTLR_BASE,
                                  TEGRA_ICTLR_SIZE * TEGRA_ICTLR_COUNT);

    if ( !tegra_ictlr_base )
        panic("Failed to map in the Tegra legacy interrupt controller!\n");

    /* Initialize each of the legacy interrupt controllers. */
    for (i = 0; i < TEGRA_ICTLR_COUNT; i++)
    {
        void __iomem *ictlr_n = tegra_ictlr_base + TEGRA_ICTLR_SIZE * i;

        /* Clear the interrupt enables for every interrupt. */
        writel(~0, ictlr_n + TEGRA_ICTLR_CPU_IER_CLR);

        /*
         * Mark all of our interrupts as normal ARM interrupts (as opposed
         * to Fast Interrupts.)
         */
        writel(0, ictlr_n + TEGRA_ICTLR_CPU_IEP_CLASS);
    }

    return 0;
}

/**
 *  Startup code for the Tegra.
 */
static int tegra_init(void)
{
    int rc;

    rc = tegra_initialize_legacy_interrupt_controller();

    /*
     * TODO: Virtualize the MMIO regions for the ictlr, ensuring the hwdom
     * (and possibly passhtrough domains) can only access ictlr registers for
     * interrupts they actually own.
     */

    return rc;
}


static const char * const tegra_dt_compat[] __initconst =
{
    "nvidia,tegra120",  /* Tegra K1 */
    "nvidia,tegra210",  /* Tegra X1 */
    NULL
};

static const struct dt_device_match tegra_blacklist_dev[] __initconst =
{
    /*
     * The UARTs share a page which runs the risk of mapping the Xen console
     * UART to dom0, so don't map any of them.
     */
    DT_MATCH_COMPATIBLE("nvidia,tegra20-uart"),
    { /* sentinel */ },
};

PLATFORM_START(tegra, "Tegra")
    .blacklist_dev = tegra_blacklist_dev,
    .compatible = tegra_dt_compat,
    .init = tegra_init,
    .reset = tegra_reset,
    .irq_is_routable = tegra_irq_is_routable,
    .irq_for_device = tegra_irq_for_device,
    .route_irq_to_xen = tegra_route_irq_to_xen,
    .route_irq_to_guest = tegra_route_irq_to_guest,
PLATFORM_END
