/*
 * Copyright (c) 2019-2023, Intel Corporation. All rights reserved.
 * Copyright (c) 2024, Altera Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef N5X_SOCFPGA_SYSTEMMANAGER_H
#define N5X_SOCFPGA_SYSTEMMANAGER_H

#include "socfpga_plat_def.h"

/* System Manager Register Map */
#define SOCFPGA_SYSMGR_SILICONID_1			0x00
#define SOCFPGA_SYSMGR_SILICONID_2			0x04
#define SOCFPGA_SYSMGR_WDDBG				0x08
#define SOCFPGA_SYSMGR_MPU_STATUS			0x10
#define SOCFPGA_SYSMGR_SDMMC_L3_MASTER			0x2C
#define SOCFPGA_SYSMGR_NAND_L3_MASTER			0x34
#define SOCFPGA_SYSMGR_USB0_L3_MASTER			0x38
#define SOCFPGA_SYSMGR_USB1_L3_MASTER			0x3C
#define SOCFPGA_SYSMGR_TSN_GLOBAL			0x40
#define SOCFPGA_SYSMGR_EMAC_0				0x44 /* TSN_0 */
#define SOCFPGA_SYSMGR_EMAC_1				0x48 /* TSN_1 */
#define SOCFPGA_SYSMGR_EMAC_2				0x4C /* TSN_2 */
#define SOCFPGA_SYSMGR_TSN_0_ACE			0x50
#define SOCFPGA_SYSMGR_TSN_1_ACE			0x54
#define SOCFPGA_SYSMGR_TSN_2_ACE			0x58
#define SOCFPGA_SYSMGR_FPGAINTF_EN_1			0x68
#define SOCFPGA_SYSMGR_FPGAINTF_EN_2			0x6C
#define SOCFPGA_SYSMGR_FPGAINTF_EN_3			0x70
#define SOCFPGA_SYSMGR_DMAC0_L3_MASTER			0x74
#define SOCFPGA_SYSMGR_ETR_L3_MASTER			0x78
#define SOCFPGA_SYSMGR_DMAC1_L3_MASTER			0x7C
#define SOCFPGA_SYSMGR_SEC_CTRL_SLT			0x80
#define SOCFPGA_SYSMGR_OSC_TRIM				0x84
#define SOCFPGA_SYSMGR_DMAC0_CTRL_STATUS_REG		0x88
#define SOCFPGA_SYSMGR_DMAC1_CTRL_STATUS_REG		0x8C
#define SOCFPGA_SYSMGR_ECC_INTMASK_VALUE		0x90
#define SOCFPGA_SYSMGR_ECC_INTMASK_SET			0x94
#define SOCFPGA_SYSMGR_ECC_INTMASK_CLR			0x98
#define SOCFPGA_SYSMGR_ECC_INTMASK_SERR			0x9C
#define SOCFPGA_SYSMGR_ECC_INTMASK_DERR			0xA0
/* NOC configuration value for Agilex5 */
#define SOCFPGA_SYSMGR_NOC_TIMEOUT			0xC0
#define SOCFPGA_SYSMGR_NOC_IDLEREQ_SET			0xC4
#define SOCFPGA_SYSMGR_NOC_IDLEREQ_CLR			0xC8
#define SOCFPGA_SYSMGR_NOC_IDLEREQ_VAL			0xCC
#define SOCFPGA_SYSMGR_NOC_IDLEACK			0xD0
#define SOCFPGA_SYSMGR_NOC_IDLESTATUS			0xD4
#define SOCFPGA_SYSMGR_FPGA2SOC_CTRL			0xD8
#define SOCFPGA_SYSMGR_FPGA_CFG				0xDC
#define SOCFPGA_SYSMGR_GPO				0xE4
#define SOCFPGA_SYSMGR_GPI				0xE8
#define SOCFPGA_SYSMGR_MPU				0xF0
#define SOCFPGA_SYSMGR_SDM_HPS_SPARE			0xF4
#define SOCFPGA_SYSMGR_HPS_SDM_SPARE			0xF8
#define SOCFPGA_SYSMGR_DFI_INTF				0xFC
#define SOCFPGA_SYSMGR_NAND_DD_CTRL			0x100
#define SOCFPGA_SYSMGR_NAND_PHY_CTRL_REG		0x104
#define SOCFPGA_SYSMGR_NAND_PHY_TSEL_REG		0x108
#define SOCFPGA_SYSMGR_NAND_DQ_TIMING_REG		0x10C
#define SOCFPGA_SYSMGR_PHY_DQS_TIMING_REG		0x110
#define SOCFPGA_SYSMGR_NAND_PHY_GATE_LPBK_CTRL_REG	0x114
#define SOCFPGA_SYSMGR_NAND_PHY_DLL_MASTER_CTRL_REG	0x118
#define SOCFPGA_SYSMGR_NAND_PHY_DLL_SLAVE_CTRL_REG	0x11C
#define SOCFPGA_SYSMGR_NAND_DD_DEFAULT_SETTING_REG0	0x120
#define SOCFPGA_SYSMGR_NAND_DD_DEFAULT_SETTING_REG1	0x124
#define SOCFPGA_SYSMGR_NAND_DD_STATUS_REG		0x128
#define SOCFPGA_SYSMGR_NAND_DD_ID_LOW_REG		0x12C
#define SOCFPGA_SYSMGR_NAND_DD_ID_HIGH_REG		0x130
#define SOCFPGA_SYSMGR_NAND_WRITE_PROT_EN_REG		0x134
#define SOCFPGA_SYSMGR_SDMMC_CMD_QUEUE_SETTING_REG	0x138
#define SOCFPGA_SYSMGR_I3C_SLV_PID_LOW			0x13C
#define SOCFPGA_SYSMGR_I3C_SLV_PID_HIGH			0x140
#define SOCFPGA_SYSMGR_I3C_SLV_CTRL_0			0x144
#define SOCFPGA_SYSMGR_I3C_SLV_CTRL_1			0x148
#define SOCFPGA_SYSMGR_F2S_BRIDGE_CTRL			0x14C
#define SOCFPGA_SYSMGR_DMA_TBU_STASH_CTRL_REG_0_DMA0	0x150
#define SOCFPGA_SYSMGR_DMA_TBU_STASH_CTRL_REG_0_DMA1	0x154
#define SOCFPGA_SYSMGR_SDM_TBU_STASH_CTRL_REG_1_SDM	0x158
#define SOCFPGA_SYSMGR_IO_TBU_STASH_CTRL_REG_2_USB2	0x15C
#define SOCFPGA_SYSMGR_IO_TBU_STASH_CTRL_REG_2_USB3	0x160
#define SOCFPGA_SYSMGR_IO_TBU_STASH_CTRL_REG_2_SDMMC	0x164
#define SOCFPGA_SYSMGR_IO_TBU_STASH_CTRL_REG_2_NAND	0x168
#define SOCFPGA_SYSMGR_IO_TBU_STASH_CTRL_REG_2_ETR	0x16C
#define SOCFPGA_SYSMGR_TSN_TBU_STASH_CTRL_REG_3_TSN0	0x170
#define SOCFPGA_SYSMGR_TSN_TBU_STASH_CTRL_REG_3_TSN1	0x174
#define SOCFPGA_SYSMGR_TSN_TBU_STASH_CTRL_REG_3_TSN2	0x178
#define SOCFPGA_SYSMGR_DMA_TBU_STREAM_CTRL_REG_0_DMA0	0x17C
#define SOCFPGA_SYSMGR_DMA_TBU_STREAM_CTRL_REG_0_DMA1	0x180
#define SOCFPGA_SYSMGR_SDM_TBU_STREAM_CTRL_REG_1_SDM	0x184
#define SOCFPGA_SYSMGR_IO_TBU_STREAM_CTRL_REG_2_USB2	0x188
#define SOCFPGA_SYSMGR_IO_TBU_STREAM_CTRL_REG_2_USB3	0x18C
#define SOCFPGA_SYSMGR_IO_TBU_STREAM_CTRL_REG_2_SDMMC	0x190
#define SOCFPGA_SYSMGR_IO_TBU_STREAM_CTRL_REG_2_NAND	0x194
#define SOCFPGA_SYSMGR_IO_TBU_STREAM_CTRL_REG_2_ETR	0x198
#define SOCFPGA_SYSMGR_TSN_TBU_STREAM_CTRL_REG_3_TSN0	0x19C
#define SOCFPGA_SYSMGR_TSN_TBU_STREAM_CTRL_REG_3_TSN1	0x1A0
#define SOCFPGA_SYSMGR_TSN_TBU_STREAM_CTRL_REG_3_TSN2	0x1A4
#define SOCFPGA_SYSMGR_DMA_TBU_STREAM_ID_AX_REG_0_DMA0	0x1A8
#define SOCFPGA_SYSMGR_DMA_TBU_STREAM_ID_AX_REG_0_DMA1	0x1AC
#define SOCFPGA_SYSMGR_SDM_TBU_STREAM_ID_AX_REG_1_SDM	0x1B0
#define SOCFPGA_SYSMGR_IO_TBU_STREAM_ID_AX_REG_2_USB2	0x1B4
#define SOCFPGA_SYSMGR_IO_TBU_STREAM_ID_AX_REG_2_USB3	0x1B8
#define SOCFPGA_SYSMGR_IO_TBU_STREAM_ID_AX_REG_2_SDMMC	0x1BC
#define SOCFPGA_SYSMGR_IO_TBU_STREAM_ID_AX_REG_2_NAND	0x1C0
#define SOCFPGA_SYSMGR_IO_TBU_STREAM_ID_AX_REG_2_ETR	0x1C4
#define SOCFPGA_SYSMGR_IO_TBU_STREAM_ID_AX_REG_2_TSN0	0x1C8
#define SOCFPGA_SYSMGR_IO_TBU_STREAM_ID_AX_REG_2_TSN1	0x1CC
#define SOCFPGA_SYSMGR_IO_TBU_STREAM_ID_AX_REG_2_TSN2	0x1D0
#define SOCFPGA_SYSMGR_USB3_MISC_CTRL_REG0		0x1F0
#define SOCFPGA_SYSMGR_USB3_MISC_CTRL_REG1		0x1F4

#define SOCFPGA_SYSMGR_BOOT_SCRATCH_COLD_0		0x200
#define SOCFPGA_SYSMGR_BOOT_SCRATCH_COLD_1		0x204
#define SOCFPGA_SYSMGR_BOOT_SCRATCH_COLD_2		0x208
#define SOCFPGA_SYSMGR_BOOT_SCRATCH_COLD_3		0x20C
#define SOCFPGA_SYSMGR_BOOT_SCRATCH_COLD_4		0x210
#define SOCFPGA_SYSMGR_BOOT_SCRATCH_COLD_5		0x214
#define SOCFPGA_SYSMGR_BOOT_SCRATCH_COLD_6		0x218
#define SOCFPGA_SYSMGR_BOOT_SCRATCH_COLD_7		0x21C
#define SOCFPGA_SYSMGR_BOOT_SCRATCH_COLD_8		0x220
#define SOCFPGA_SYSMGR_BOOT_SCRATCH_COLD_9		0x224
#define SOCFPGA_SYSMGR_MPFE_CONFIG			0x228
#define SOCFPGA_SYSMGR_MPFE_STATUS			0x22C
#define SOCFPGA_SYSMGR_BOOT_SCRATCH_WARM_0		0x230
#define SOCFPGA_SYSMGR_BOOT_SCRATCH_WARM_1		0x234
#define SOCFPGA_SYSMGR_BOOT_SCRATCH_WARM_2		0x238
#define SOCFPGA_SYSMGR_BOOT_SCRATCH_WARM_3		0x23C
#define SOCFPGA_SYSMGR_BOOT_SCRATCH_WARM_4		0x240
#define SOCFPGA_SYSMGR_BOOT_SCRATCH_WARM_5		0x244
#define SOCFPGA_SYSMGR_BOOT_SCRATCH_WARM_6		0x248
#define SOCFPGA_SYSMGR_BOOT_SCRATCH_WARM_7		0x24C
#define SOCFPGA_SYSMGR_BOOT_SCRATCH_WARM_8		0x250
#define SOCFPGA_SYSMGR_BOOT_SCRATCH_WARM_9		0x254
#define SOCFPGA_SYSMGR_BOOT_SCRATCH_POR_0		0x258
#define SOCFPGA_SYSMGR_BOOT_SCRATCH_POR_1		0x25C
#define SOCFPGA_SYSMGR_BOOT_SCRATCH_POR_2		0x260
#define SOCFPGA_SYSMGR_BOOT_SCRATCH_POR_3		0x264
#define SOCFPGA_SYSMGR_BOOT_SCRATCH_POR_4		0x268
#define SOCFPGA_SYSMGR_BOOT_SCRATCH_POR_5		0x26C
#define SOCFPGA_SYSMGR_BOOT_SCRATCH_POR_6		0x270
#define SOCFPGA_SYSMGR_BOOT_SCRATCH_POR_7		0x274
#define SOCFPGA_SYSMGR_BOOT_SCRATCH_POR_8		0x278
#define SOCFPGA_SYSMGR_BOOT_SCRATCH_POR_9		0x27C

/* QSPI ECC from SDM register */
#define SOCFPGA_ECC_QSPI_CTRL						0x08
#define SOCFPGA_ECC_QSPI_ERRINTEN					0x10
#define SOCFPGA_ECC_QSPI_ERRINTENS					0x14
#define SOCFPGA_ECC_QSPI_ERRINTENR					0x18
#define SOCFPGA_ECC_QSPI_INTMODE					0x1C
#define SOCFPGA_ECC_QSPI_INTSTAT					0x20
#define SOCFPGA_ECC_QSPI_INTTEST					0x24
#define SOCFPGA_ECC_QSPI_ECC_ACCCTRL					0x78
#define SOCFPGA_ECC_QSPI_ECC_STARTACC					0x7C
#define SOCFPGA_ECC_QSPI_ECC_WDCTRL					0x80

#define DMA0_STREAM_CTRL_REG				0x10D1217C
#define DMA1_STREAM_CTRL_REG				0x10D12180
#define SDM_STREAM_CTRL_REG				0x10D12184
#define USB2_STREAM_CTRL_REG				0x10D12188
#define USB3_STREAM_CTRL_REG				0x10D1218C
#define SDMMC_STREAM_CTRL_REG				0x10D12190
#define NAND_STREAM_CTRL_REG				0x10D12194
#define ETR_STREAM_CTRL_REG				0x10D12198
#define TSN0_STREAM_CTRL_REG				0x10D1219C
#define TSN1_STREAM_CTRL_REG				0x10D121A0
#define TSN2_STREAM_CTRL_REG				0x10D121A4

/* Stream ID configuration value for Agilex5 */
#define TSN0						0x00010001
#define TSN1						0x00020002
#define TSN2						0x00030003
#define NAND						0x00040004
#define SDMMC						0x00050005
#define USB0						0x00060006
#define USB1						0x00070007
#define DMA0						0x00080008
#define DMA1						0x00090009
#define SDM						0x000A000A
#define CORE_SIGHT_DEBUG				0x000B000B




/* Field Masking */
#define SYSMGR_SDMMC_DRVSEL(x)				(((x) & 0x7) << 0)
#define SYSMGR_SDMMC_SMPLSEL(x)				(((x) & 0x7) << 4)
#define IDLE_DATA_LWSOC2FPGA				BIT(4)
#define IDLE_DATA_SOC2FPGA				BIT(0)
#define IDLE_DATA_MASK					(IDLE_DATA_LWSOC2FPGA | IDLE_DATA_SOC2FPGA)
#define SYSMGR_ECC_OCRAM_MASK				BIT(1)
#define SYSMGR_ECC_DDR0_MASK				BIT(16)
#define SYSMGR_ECC_DDR1_MASK				BIT(17)
#define WSTREAMIDEN_REG_CTRL				BIT(0)
#define RSTREAMIDEN_REG_CTRL				BIT(1)
#define WMMUSECSID_REG_VAL				BIT(4)
#define RMMUSECSID_REG_VAL				BIT(5)

/* Macros */
#define SOCFPGA_ECC_QSPI(_reg)						(SOCFPGA_ECC_QSPI_REG_BASE \
									+ (SOCFPGA_ECC_QSPI_##_reg))

#define SOCFPGA_SYSMGR(_reg)				(SOCFPGA_SYSMGR_REG_BASE \
								+ (SOCFPGA_SYSMGR_##_reg))
#define ENABLE_STREAMID					WSTREAMIDEN_REG_CTRL | \
							RSTREAMIDEN_REG_CTRL
#define ENABLE_STREAMID_SECURE_TX			WSTREAMIDEN_REG_CTRL | \
							RSTREAMIDEN_REG_CTRL | \
							WMMUSECSID_REG_VAL | RMMUSECSID_REG_VAL

#endif /* N5X_SOCFPGA_SYSTEMMANAGER_H */