/*
 * Copyright (C) 2019 Christian Amsüss <chrysn@fsfe.org>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     boards_nrf52840-dongle
 * @{
 *
 * @file
 * @brief       Configuration of SAUL mapped GPIO pins
 *
 * @author      Christian Amsüss <chrysn@fsfe.org>
 */

#ifndef GPIO_PARAMS_H
#define GPIO_PARAMS_H

#include "board.h"
#include "saul/periph.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief    LED configuration
 */
static const  saul_gpio_params_t saul_gpio_params[] =
{
    {
        .name  = "LED 1",
        .pin   = LED0_PIN,
        .mode  = GPIO_OUT,
        .flags = SAUL_GPIO_INIT_CLEAR,
    },
    {
        .name  = "LED 2 Red",
        .pin   = LED1_PIN,
        .mode  = GPIO_OUT,
        .flags = SAUL_GPIO_INIT_CLEAR,
    },
    {
        .name  = "LED 2 Green",
        .pin   = LED2_PIN,
        .mode  = GPIO_OUT,
        .flags = SAUL_GPIO_INIT_CLEAR,
    },
    {
        .name  = "LED 2 Blue",
        .pin   = LED3_PIN,
        .mode  = GPIO_OUT,
        .flags = SAUL_GPIO_INIT_CLEAR,
    },
    {
        .name  = "Button 1",
        .pin   = BTN0_PIN,
        .mode  = GPIO_IN_PU,
        .flags = SAUL_GPIO_INVERTED,
    },
};


#ifdef __cplusplus
}
#endif

#endif /* GPIO_PARAMS_H */
/** @} */
