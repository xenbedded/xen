/*
 * xen/arch/arm/tegra_mlic.c
 *
 * Mediator for Tegra Legacy Interrupt Controller
 *
 * This module allow the hardware domain to have access to the sections of
 * the legacy interrupt controller that correspond to its devices,
 * but disallow access to the sections controlled by other domains
 * or by Xen.
 *
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

#include <xen/lib.h>
#include <xen/stdbool.h>
#include <xen/sched.h>
#include <xen/vmap.h>
#include <xen/iocap.h>

#include <asm/io.h>
#include <asm/gic.h>
#include <asm/platform.h>
#include <asm/platforms/tegra.h>
#include <asm/platforms/tegra-mlic.h>
#include <asm/mmio.h>
#include <xen/perfc.h>

static int tegra_mlic_mmio_read(struct vcpu *v, mmio_info_t *info,
                           register_t *r, void *priv);
static int tegra_mlic_mmio_write(struct vcpu *v, mmio_info_t *info,
                            register_t r, void *priv);

static const struct mmio_handler_ops tegra_mlic_mmio_handler = {
    .read  = tegra_mlic_mmio_read,
    .write = tegra_mlic_mmio_write,
};

/*
 * Parses a LIC MMIO read or write, and extracts the information needed to
 * complete the request.
 *
 * info: Information describing the MMIO read/write being performed
 * ictlr_index: The interrupt controller number in the ictlr (e.g. 0-5)
 * register_offset: The register offset into the specified interrupt controller
 *        (e.g. TEGRA_ICTLR_CPU_IER_SET)
 * irq_base: The number of the first IRQ represented by the given ictlr.
 */
static void tegra_mlic_parse_mmio_request(mmio_info_t *info,
    uint32_t *ictlr_index, uint32_t *register_offset, uint32_t *irq_base)
{
    /* Determine the offset of the access into the ICTLR region. */
    uint32_t offset = info->gpa - TEGRA_ICTLR_BASE;
    uint32_t ictlr = offset / TEGRA_ICTLR_SIZE;
    uint32_t reg = offset % TEGRA_ICTLR_SIZE;

    if ( ictlr_index )
        *ictlr_index = ictlr;

    if ( register_offset )
        *register_offset = reg;

    if ( irq_base )
        *irq_base = (ictlr * TEGRA_IRQS_PER_ICTLR) + NR_LOCAL_IRQS;

    /* Ensure that we've only been handed a valid offset within our region. */
    BUG_ON(ictlr >= TEGRA_ICTLR_COUNT);
    BUG_ON(offset >= (TEGRA_ICTLR_COUNT * TEGRA_ICTLR_SIZE));
    BUG_ON((ictlr * TEGRA_ICTLR_SIZE + reg) != offset);
}

/*
 * Returns true iff the given IRQ is currently routed to the given domain.
 */
static bool irq_owned_by_domain(int irq, struct domain *d)
{
    struct irq_desc *desc = irq_to_desc(irq);
    domid_t domid;
    unsigned long flags;

    BUG_ON(!desc);

    spin_lock_irqsave(&desc->lock, flags);
    domid = irq_get_domain_id(desc);
    spin_unlock_irqrestore(&desc->lock, flags);

    return (d->domain_id == domid);
}

/*
 * Mediates an MMIO-read to the Tegra legacy interrupt controller.
 * Ensures that each domain only is passed interrupt state for its
 * own interupts.
 */
static int tegra_mlic_mmio_read(struct vcpu *v, mmio_info_t *info,
                                register_t *target_register, void *priv)
{
    register_t raw_value;
    unsigned int ictlr_index;
    unsigned int register_offset;
    unsigned int irq_base;
    int i;

    perfc_incr(tegra_mlic_reads);

    tegra_mlic_parse_mmio_request(info, &ictlr_index, &register_offset,
                                       &irq_base);

    /* Sanity check the read. */
    if ( register_offset & 0x3 )
    {
        printk(XENLOG_G_ERR "d%u: Tegra LIC: Attempt to read unaligned ictlr addr"
                            "(%" PRIpaddr ")\n", current->domain->domain_id, info->gpa);
        domain_crash_synchronous();
    }

    if ( info->dabt.size != DABT_WORD )
    {
        printk(XENLOG_G_ERR "d%u: Tegra LIC: Non-word read from ictlr addr"
                            "%" PRIpaddr "\n", current->domain->domain_id, info->gpa);
        domain_crash_synchronous();
    }


    /* Perform the core ictlr read. */
    raw_value = tegra_lic_readl(ictlr_index, register_offset);

    /*
     * We don't want to leak information about interrupts not controlled
     * by the active domain. Thus, we'll zero out any ictlr slots for
     * IRQs not owned by the given domain.
     */
    for ( i = 0; i < TEGRA_IRQS_PER_ICTLR; ++i ) {
        int irq = irq_base + i;

        if ( !irq_owned_by_domain(irq, current->domain) )
            raw_value &= ~( 1 << i );
    }

    /* Finally, set the target register to our read value */
    *target_register = raw_value;
    return 1;
}

/*
 * Mediates an MMIO-read to the Tegra legacy interrupt controller.
 * Ensures that each domain only can only control is own interrupts.
 */
static int tegra_mlic_mmio_write(struct vcpu *v, mmio_info_t *info,
                                   register_t new_value, void *priv)
{
    register_t write_mask = 0;
    register_t raw_value;
    unsigned int ictlr_index;
    unsigned int register_offset;
    unsigned int irq_base;
    int i;

    perfc_incr(tegra_mlic_writes);

    tegra_mlic_parse_mmio_request(info, &ictlr_index, &register_offset,
                                  &irq_base);

    /* Sanity check the read. */
    if ( register_offset & 0x3 ) {
        printk(XENLOG_G_ERR "d%u: Tegra LIC: Attempt to write unaligned ictlr addr"
                            "(%" PRIpaddr ")\n", current->domain->domain_id, info->gpa);
        domain_crash_synchronous();
        return 0;
    }

    if ( info->dabt.size != DABT_WORD ) {
        printk(XENLOG_G_ERR "d%u: Tegra LIC: Non-word write to ictlr addr"
                            "%" PRIpaddr "\n", current->domain->domain_id, info->gpa);
        domain_crash_synchronous();
        return 0;
    }

    /*
     * We only want to write to bits that correspond to interrupts that the
     * current domain controls. Accordingly, we'll create a mask that has a
     * single bit set for each writable bit.
     */
    for ( i = 0; i < TEGRA_IRQS_PER_ICTLR; ++i ) {
        int irq = irq_base + i;

        if ( irq_owned_by_domain(irq, current->domain) )
            write_mask |= ( 1 << i );
    }

    /*
     * Read in the original value. We'll use this to ensure that we maintain
     * the bit values for any bits not actively controlled by this domain. Note
     * that we can perform this read without side effects, so this shouldn't
     * change the actual operation being performed.
     */
    raw_value = tegra_lic_readl(ictlr_index, register_offset);

    /* Remove bits that the guest is not allowed to write. */
    raw_value &= ~write_mask;
    raw_value |= (write_mask & new_value);

    /* Finally perform the write. */
    tegra_lic_writel(ictlr_index, register_offset, raw_value);
    return 1;
}

/*
 * Set up the hardware domain for the Tegra, giving it mediated access to the
 * platform's legacy interrupt controller.
 */
int domain_tegra_mlic_init(struct domain *d)
{
    int rc;
    unsigned long pfn_start, pfn_end;

    ASSERT( is_hardware_domain(d) );

    pfn_start = paddr_to_pfn(TEGRA_ICTLR_BASE);
    pfn_end = DIV_ROUND_UP(TEGRA_ICTLR_BASE + (TEGRA_ICTLR_SIZE * TEGRA_ICTLR_COUNT), PAGE_SIZE);

    /* Force all access to the ictlr to go through our mediator. */
    rc = iomem_deny_access(d, pfn_start, pfn_end);

    if ( rc )
        panic("Failed to deny access to the Tegra LIC iomem");

    rc = unmap_mmio_regions(d, _gfn(pfn_start),
                            pfn_end - pfn_start + 1,
                            _mfn(pfn_start));

    if ( rc )
        panic("Failed to deny access to the Tegra LIC");

    register_mmio_handler(d, &tegra_mlic_mmio_handler,
                          TEGRA_ICTLR_BASE,
                          TEGRA_ICTLR_SIZE * TEGRA_ICTLR_COUNT,
                          NULL);

    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
