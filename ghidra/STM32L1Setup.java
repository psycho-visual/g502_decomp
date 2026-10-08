// Pre-analysis script for G502 HERO application images (raw .bin loaded at 0x08004000,
// language ARM:LE:32:Cortex). Adds the STM32L1 (medium density) memory map, peripheral
// register structs, and names/creates the vector table handlers.
//@category G502

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;

public class STM32L1Setup extends GhidraScript {

	private static final CategoryPath CAT = new CategoryPath("/STM32L1");

	private static final String[] CORE_VECTORS = {
		"initial_sp", "Reset_Handler", "NMI_Handler", "HardFault_Handler", "MemManage_Handler",
		"BusFault_Handler", "UsageFault_Handler", null, null, null, null, "SVC_Handler",
		"DebugMon_Handler", null, "PendSV_Handler", "SysTick_Handler"
	};

	// startup_stm32l1xx_md.s IRQ order
	private static final String[] IRQS = {
		"WWDG", "PVD", "TAMPER_STAMP", "RTC_WKUP", "FLASH", "RCC", "EXTI0", "EXTI1", "EXTI2",
		"EXTI3", "EXTI4", "DMA1_Channel1", "DMA1_Channel2", "DMA1_Channel3", "DMA1_Channel4",
		"DMA1_Channel5", "DMA1_Channel6", "DMA1_Channel7", "ADC1", "USB_HP", "USB_LP", "DAC",
		"COMP", "EXTI9_5", "LCD", "TIM9", "TIM10", "TIM11", "TIM2", "TIM3", "TIM4", "I2C1_EV",
		"I2C1_ER", "I2C2_EV", "I2C2_ER", "SPI1", "SPI2", "USART1", "USART2", "USART3",
		"EXTI15_10", "RTC_Alarm", "USB_FS_WKUP", "TIM6", "TIM7"
	};

	private void block(String name, long start, long size, boolean isVolatile, boolean exec)
			throws Exception {
		Address a = toAddr(start);
		Memory m = currentProgram.getMemory();
		if (m.getBlock(a) != null) {
			return;
		}
		MemoryBlock b = m.createUninitializedBlock(name, a, size, false);
		b.setPermissions(true, true, exec);
		b.setVolatile(isVolatile);
	}

	/** Register struct of 32-bit registers; null names are reserved slots. */
	private DataType regs(String name, String... fields) {
		StructureDataType s = new StructureDataType(CAT, name, 0);
		int rsv = 0;
		for (String f : fields) {
			s.add(DWordDataType.dataType, f != null ? f : "RESERVED" + rsv++, null);
		}
		return currentProgram.getDataTypeManager()
				.addDataType(s, DataTypeConflictHandler.REPLACE_HANDLER);
	}

	private void periph(String name, long addr, DataType t) throws Exception {
		Address a = toAddr(addr);
		createLabel(a, name, true, SourceType.USER_DEFINED);
		clearListing(a, a.add(t.getLength() - 1));
		createData(a, t);
	}

	@Override
	public void run() throws Exception {
		// Flash is read-only: lets the decompiler fold literal-pool constants into addresses.
		MemoryBlock app = currentProgram.getMemory().getBlock(toAddr(0x08004000L));
		app.setName("APP_FLASH");
		app.setPermissions(true, false, true);

		block("BOOTLOADER", 0x08000000L, 0x4000, false, true);
		block("FLASH_HI", 0x0800EF00L, 0x1100, false, false);
		block("DATA_EEPROM", 0x08080000L, 0x1000, false, false);
		block("SYSMEM_OPT", 0x1FF00000L, 0x81000, false, false);
		block("SRAM", 0x20000000L, 0x4000, false, false);
		block("APB1", 0x40000000L, 0x8000, true, false);
		block("APB2", 0x40010000L, 0x4000, true, false);
		block("AHB", 0x40020000L, 0x8000, true, false);
		block("SCS", 0xE000E000L, 0x1000, true, false);

		DataType gpio = regs("GPIO_TypeDef", "MODER", "OTYPER", "OSPEEDR", "PUPDR", "IDR", "ODR",
			"BSRR", "LCKR", "AFRL", "AFRH", "BRR");
		DataType tim = regs("TIM_TypeDef", "CR1", "CR2", "SMCR", "DIER", "SR", "EGR", "CCMR1",
			"CCMR2", "CCER", "CNT", "PSC", "ARR", null, "CCR1", "CCR2", "CCR3", "CCR4", null, "DCR",
			"DMAR", "OR");
		DataType exti = regs("EXTI_TypeDef", "IMR", "EMR", "RTSR", "FTSR", "SWIER", "PR");
		DataType spi = regs("SPI_TypeDef", "CR1", "CR2", "SR", "DR", "CRCPR", "RXCRCR", "TXCRCR",
			"I2SCFGR", "I2SPR");
		DataType rcc = regs("RCC_TypeDef", "CR", "ICSCR", "CFGR", "CIR", "AHBRSTR", "APB2RSTR",
			"APB1RSTR", "AHBENR", "APB2ENR", "APB1ENR", "AHBLPENR", "APB2LPENR", "APB1LPENR", "CSR");
		DataType flash = regs("FLASH_TypeDef", "ACR", "PECR", "PDKEYR", "PEKEYR", "PRGKEYR",
			"OPTKEYR", "SR", "OBR", "WRPR");
		DataType syscfg = regs("SYSCFG_TypeDef", "MEMRMP", "PMC", "EXTICR1", "EXTICR2", "EXTICR3",
			"EXTICR4");
		DataType pwr = regs("PWR_TypeDef", "CR", "CSR");
		DataType iwdg = regs("IWDG_TypeDef", "KR", "PR", "RLR", "SR");
		DataType rtc = regs("RTC_TypeDef", "TR", "DR", "CR", "ISR", "PRER", "WUTR", "CALIBR",
			"ALRMAR", "ALRMBR", "WPR", "SSR", "SHIFTR", "TSTR", "TSDR", "TSSSR", "CALR", "TAFCR",
			"ALRMASSR", "ALRMBSSR");
		DataType usb = regs("USB_TypeDef", "EP0R", "EP1R", "EP2R", "EP3R", "EP4R", "EP5R", "EP6R",
			"EP7R", null, null, null, null, null, null, null, null, "CNTR", "ISTR", "FNR", "DADDR",
			"BTABLE");
		DataType crc = regs("CRC_TypeDef", "DR", "IDR", "CR");
		DataType systick = regs("SysTick_Type", "CTRL", "LOAD", "VAL", "CALIB");
		DataType dma = regs("DMA_Channel_TypeDef", "CCR", "CNDTR", "CPAR", "CMAR");
		DataType scb = regs("SCB_Type", "CPUID", "ICSR", "VTOR", "AIRCR", "SCR", "CCR", "SHP0",
			"SHP1", "SHP2", "SHCSR", "CFSR", "HFSR", "DFSR", "MMFAR", "BFAR", "AFSR");

		periph("TIM2", 0x40000000L, tim);
		periph("TIM3", 0x40000400L, tim);
		periph("TIM4", 0x40000800L, tim);
		periph("TIM6", 0x40001000L, tim);
		periph("TIM7", 0x40001400L, tim);
		periph("RTC", 0x40002800L, rtc);
		periph("IWDG", 0x40003000L, iwdg);
		periph("SPI2", 0x40003800L, spi);
		periph("USB", 0x40005C00L, usb);
		periph("PWR", 0x40007000L, pwr);
		periph("SYSCFG", 0x40010000L, syscfg);
		periph("EXTI", 0x40010400L, exti);
		periph("TIM9", 0x40010800L, tim);
		periph("TIM10", 0x40010C00L, tim);
		periph("TIM11", 0x40011000L, tim);
		periph("SPI1", 0x40013000L, spi);
		periph("GPIOA", 0x40020000L, gpio);
		periph("GPIOB", 0x40020400L, gpio);
		periph("GPIOC", 0x40020800L, gpio);
		periph("GPIOD", 0x40020C00L, gpio);
		periph("GPIOH", 0x40021400L, gpio);
		periph("CRC", 0x40023000L, crc);
		periph("RCC", 0x40023800L, rcc);
		periph("FLASH", 0x40023C00L, flash);
		for (int ch = 1; ch <= 7; ch++) {
			periph("DMA1_Channel" + ch, 0x40026008L + 20L * (ch - 1), dma);
		}
		periph("SysTick", 0xE000E010L, systick);
		periph("SCB", 0xE000ED00L, scb);
		createLabel(toAddr(0xE000E100L), "NVIC_ISER", true, SourceType.USER_DEFINED);
		createLabel(toAddr(0xE000E180L), "NVIC_ICER", true, SourceType.USER_DEFINED);
		createLabel(toAddr(0xE000E200L), "NVIC_ISPR", true, SourceType.USER_DEFINED);
		createLabel(toAddr(0xE000E280L), "NVIC_ICPR", true, SourceType.USER_DEFINED);
		createLabel(toAddr(0xE000E400L), "NVIC_IPR", true, SourceType.USER_DEFINED);
		createLabel(toAddr(0x1FF80050L), "DEVICE_UID", true, SourceType.USER_DEFINED);

		// Vector table
		Address vt = toAddr(0x08004000L);
		int n = CORE_VECTORS.length + IRQS.length;
		createLabel(vt, "g_vector_table", true, SourceType.USER_DEFINED);
		java.util.Map<Long, Integer> uses = new java.util.HashMap<>();
		for (int i = 1; i < n; i++) {
			uses.merge(getInt(vt.add(4L * i)) & 0xFFFFFFFFL, 1, Integer::sum);
		}
		for (int i = 0; i < n; i++) {
			Address slot = vt.add(4L * i);
			clearListing(slot, slot.add(3));
			createData(slot, PointerDataType.dataType);
			if (i == 0) {
				continue;
			}
			long v = getInt(slot) & 0xFFFFFFFFL;
			String name = i < CORE_VECTORS.length ? CORE_VECTORS[i]
					: IRQS[i - CORE_VECTORS.length] + "_IRQHandler";
			if (v == 0 || name == null) {
				continue;
			}
			if (uses.get(v) > 1) {
				name = "Default_Handler";
			}
			Address h = toAddr(v & ~1L);
			if (getSymbolAt(h) != null && getSymbolAt(h).getSource() == SourceType.USER_DEFINED) {
				continue;
			}
			createLabel(h, name, true, SourceType.USER_DEFINED);
			disassemble(h);
			createFunction(h, name);
		}
	}
}
