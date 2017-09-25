/*
 * Copyright (C) 2014-2016 Freie Universität Berlin
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     cpu_efm32_common
 *
 * @{
 *
 * @file
 * @brief       Low-level SPI driver implementation
 *
 * @author      Ryan Kurte <ryankurte@gmail.com>
 * @author      Bas Stottelaar <basstottelaar@gmail.com>
 *
 * @}
 */

#include "cpu.h"
#include "sched.h"
#include "thread.h"
#include "mutex.h"

#include "periph_conf.h"
#include "periph/gpio.h"
#include "periph/spi.h"

#include "em_device.h"
#include "em_cmu.h"
#include "em_usart.h"
#include "em_common_utils.h"

void poweroff(spi_t bus);
void poweron(spi_t bus);

/* FIXME: I think this should not only lock on SPI devices, but also on their .dev */
static mutex_t spi_lock[SPI_NUMOF];

void spi_init(spi_t bus)
{
    assert(bus <= SPI_NUMOF);

    mutex_init(&spi_lock[bus]);
}

int conf_pins(spi_t bus)
{
    /* configure the pins */
    gpio_init(spi_config[bus].clk_pin, GPIO_OUT);
    gpio_init(spi_config[bus].mosi_pin, GPIO_OUT);
    gpio_init(spi_config[bus].miso_pin, GPIO_IN_PD);

    gpio_set(spi_config[bus].clk_pin);
    gpio_set(spi_config[bus].mosi_pin);

    /* configure pin functions */
#ifdef _SILICON_LABS_32B_PLATFORM_1
    spi_config[bus].dev->ROUTE = (spi_config[bus].loc |
                                  USART_ROUTE_RXPEN |
                                  USART_ROUTE_TXPEN |
                                  USART_ROUTE_CLKPEN);
#else
    spi_config[bus].dev->ROUTELOC0 = spi_config[bus].loc;
    spi_config[bus].dev->ROUTEPEN = (USART_ROUTEPEN_RXPEN |
                                     USART_ROUTEPEN_TXPEN |
                                     USART_ROUTEPEN_CLKPEN);
#endif

    return 0;
}

int spi_acquire(spi_t bus, spi_cs_t cs, spi_mode_t mode, spi_clk_t clk)
{
    mutex_lock((mutex_t *) &spi_lock[bus]);

    poweron(bus);

    CMU_ClockEnable(cmuClock_HFPER, true);
    CMU_ClockEnable(spi_config[bus].cmu, true);

    EFM32_CREATE_INIT(init, USART_InitSync_TypeDef, USART_INITSYNC_DEFAULT,
        .conf.baudrate = (uint32_t) clk,
        .conf.clockMode = (USART_ClockMode_TypeDef) mode,
        .conf.msbf = true
    );

    USART_InitSync(spi_config[bus].dev, &init.conf);

    /* configure the pins */
    conf_pins(bus);

    return SPI_OK;
}

void spi_release(spi_t bus)
{
    /** FIXME this should swich things off again -- but how to properly switch off HFPER? */

    poweroff(bus);

    mutex_unlock((mutex_t *) &spi_lock[bus]);
}

void spi_transfer_bytes(spi_t bus, spi_cs_t cs, bool cont,
                        const void *out, void *in, size_t len)
{
    uint8_t *out_buf = (uint8_t *)out;
    uint8_t *in_buf = (uint8_t *)in;

    if (cs != SPI_CS_UNDEF) {
        gpio_clear((gpio_t)cs);
    }

    for (size_t i = 0; i < len; i++) {
        uint8_t ret = USART_SpiTransfer(spi_config[bus].dev, out != NULL ? out_buf[i] : 0);
        if (in != NULL)
            in_buf[i] = ret;
    }

    if ((!cont) && (cs != SPI_CS_UNDEF)) {
        gpio_set((gpio_t)cs);
    }
}

void poweron(spi_t bus)
{
    CMU_ClockEnable(spi_config[bus].cmu, true);
}

void poweroff(spi_t bus)
{
    CMU_ClockEnable(spi_config[bus].cmu, false);
}

