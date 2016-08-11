/*
 * NVIDIA Tegra platform definitions
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


#ifndef __ASM_ARM_PLATFORMS_TEGRA_H
#define __ASM_ARM_PLATFORMS_TEGRA_H

#define   TEGRA_ICTLR_BASE            0x60004000
#define   TEGRA_ICTLR_SIZE            0x00000100
#define   TEGRA_ICTLR_COUNT           6
#define   TEGRA_IRQS_PER_ICTLR        32

#define   TEGRA_ICTLR_CPU_IER         0x20
#define   TEGRA_ICTLR_CPU_IER_SET     0x24
#define   TEGRA_ICTLR_CPU_IER_CLR     0x28
#define   TEGRA_ICTLR_CPU_IEP_CLASS   0x2C

#define   TEGRA_ICTLR_COP_IER         0x30
#define   TEGRA_ICTLR_COP_IER_SET     0x34
#define   TEGRA_ICTLR_COP_IER_CLR     0x38
#define   TEGRA_ICTLR_COP_IEP_CLASS   0x3c

#define   TEGRA_RESET_BASE            0x7000e400
#define   TEGRA_RESET_SIZE            4
#define   TEGRA_RESET_MASK            0x10

uint32_t tegra_lic_readl(unsigned int ictlr_index, unsigned int register_offset);
void tegra_lic_writel(unsigned int ictlr_index, unsigned int register_offset, uint32_t value);

#endif /* __ASM_ARM_PLATFORMS_TEGRA_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
