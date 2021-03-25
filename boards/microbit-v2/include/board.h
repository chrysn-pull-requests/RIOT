/*
 * Copyright (C) 2021 Inria
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     boards_microbit_v2
 * @{
 *
 * @file
 * @brief       Board specific configuration for the BBC micro:bit v2
 *
 * @author      Alexandre Abadie <alexandre.abadie@inria.fr>
 */

#ifndef BOARD_H
#define BOARD_H

#include "board_common.h"

#if IS_USED(MODULE_PWM_DAC)
#include "pwm_dac_for_board.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @name    LED matrix pin configuration
 * @{
 */
#define MICROBIT_LED_COL1           GPIO_PIN(0, 28)
#define MICROBIT_LED_COL2           GPIO_PIN(0, 11)
#define MICROBIT_LED_COL3           GPIO_PIN(0, 31)
#define MICROBIT_LED_COL4           GPIO_PIN(1,  5)
#define MICROBIT_LED_COL5           GPIO_PIN(0, 30)
#define MICROBIT_LED_ROW1           GPIO_PIN(0, 21)
#define MICROBIT_LED_ROW2           GPIO_PIN(0, 22)
#define MICROBIT_LED_ROW3           GPIO_PIN(0, 15)
#define MICROBIT_LED_ROW4           GPIO_PIN(0, 24)
#define MICROBIT_LED_ROW5           GPIO_PIN(0, 19)
/** @} */

/**
 * @name    Button configuration
 * @{
 */
#define BTN0_PIN                    GPIO_PIN(0, 14)
#define BTN0_MODE                   GPIO_IN
#define BTN1_PIN                    GPIO_PIN(0, 23)
#define BTN1_MODE                   GPIO_IN
/** @} */

/**
 * @name    Microphone
 * @{
 */
#define RUN_MIC_PIN                 GPIO_PIN(0, 20)
#define MIC_IN_PIN                  GPIO_PIN(0,  5)
/** @} */

/**
 * @name    Speaker
 * @{
 */
#define SPEAKER_PIN                 GPIO_PIN(0, 0)
/** @} */

/**
 * @name    LSM303AGR accelerometer/magnetometer
 * @{
 */
#define LSM303AGR_PARAM_ACC_ADDR    0x19
#define LSM303AGR_PARAM_MAG_ADDR    0x1E
/** @} */

#ifdef __cplusplus
}
#endif

#endif /* BOARD_H */
/** @} */
