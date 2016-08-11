#ifndef __ASM_ARM_PLATFORMS_TEGRA_H
#define __ASM_ARM_PLATFORMS_TEGRA_H

#define   TEGRA_ICTLR_BASE            0x60004000
#define   TEGRA_ICTLR_SIZE            0x00000100
#define   TEGRA_ICTLR_COUNT           6

#define   TEGRA_RESET_BASE            0x7000e400
#define   TEGRA_RESET_SIZE            4
#define   TEGRA_RESET_MASK            0x10

#define   TEGRA_ICTLR_CPU_IER         0x20
#define   TEGRA_ICTLR_CPU_IER_SET     0x24
#define   TEGRA_ICTLR_CPU_IER_CLR     0x28
#define   TEGRA_ICTLR_CPU_IEP_CLASS   0x2C

#define   TEGRA_ICTLR_COP_IER         0x30
#define   TEGRA_ICTLR_COP_IER_SET     0x34
#define   TEGRA_ICTLR_COP_IER_CLR     0x38
#define   TEGRA_ICTLR_COP_IEP_CLASS   0x3c


#endif /* __ASM_ARM_PLATFORMS_TEGRA_H */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
