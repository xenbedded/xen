/*
 * xen/arch/arm/vuart.h
 *
 * Mediated Tegra Legacy Interrupt Controller
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

#ifndef __ASM_ARM_PLATFORMS_TEGRA_MLIC_H
#define __ASM_ARM_PLATFORMS_TEGRA_MLIC_H

int domain_tegra_mlic_init(struct domain *d);

#endif /* __ASM_ARM_PLATFORMS_TEGRA_MLIC_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
