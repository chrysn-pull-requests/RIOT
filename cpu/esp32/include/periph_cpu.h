/*
 * Copyright (C) 2022 Gunar Schorcht
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     cpu_esp32
 * @{
 *
 * @file
 * @brief       Peripheral configuration that is common for all ESP32x SoCs
 *
 * @author      Gunar Schorcht <gunar@schorcht.net>
 */

#ifndef PERIPH_CPU_H
#define PERIPH_CPU_H

#include <stdbool.h>
#include <stdint.h>
#include "sdkconfig.h"
#include "hal/ledc_types.h"
#include "hal/spi_types.h"
#include "soc/ledc_struct.h"
#include "soc/periph_defs.h"
#include "soc/soc_caps.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @name    Power management configuration
 * @{
 */
#define PROVIDES_PM_SET_LOWEST
#define PROVIDES_PM_RESTART
#define PROVIDES_PM_OFF
#define PROVIDES_PM_LAYERED_OFF

/**
 * @brief   Number of usable low power modes
 */
#define PM_NUM_MODES            (3U)

/**
 * @name    Power modes
 * @{
 */
#define ESP_PM_MODEM_SLEEP      (2U)
#define ESP_PM_LIGHT_SLEEP      (1U)
#define ESP_PM_DEEP_SLEEP       (0U)
/** @} */

/** @} */

/**
 * @brief   Length of the CPU_ID in octets
 */
#define CPUID_LEN               (6U)

/**
 * @name   GPIO configuration
 * @{
 */

/**
 * @brief   Override the default gpio_t type definition
 *
 * This is required here to have gpio_t defined in this file.
 * @{
 */
#define HAVE_GPIO_T
typedef unsigned int gpio_t;
/** @} */

/**
 * @brief   Definition of a fitting UNDEF value
 * @{
 */
#define GPIO_UNDEF          (0xffffffff)
/** @} */

/**
 * @brief   Define a CPU specific GPIO pin generator macro
 * @{
 */
#define GPIO_PIN(x, y)      ((x & 0) | y)
/** @} */

/**
 * @brief   Available GPIO ports on ESP32
 * @{
 */
#define PORT_GPIO           (0)
/** @} */

/**
 * @brief   Define CPU specific number of GPIO pins
 * @{
 */
#define GPIO_PIN_NUMOF      (SOC_GPIO_PIN_COUNT)
/** @} */

#ifndef DOXYGEN
/**
 * @brief   Override mode flank selection values
 *
 * @{
 */
#define HAVE_GPIO_FLANK_T
typedef enum {
    GPIO_NONE,
    GPIO_RISING,    /**< emit interrupt on rising flank  */
    GPIO_FALLING,   /**< emit interrupt on falling flank */
    GPIO_BOTH,      /**< emit interrupt on both flanks */
    GPIO_LOW,       /**< emit interrupt on low level */
    GPIO_HIGH       /**< emit interrupt on low level */
} gpio_flank_t;
/** @} */

/**
 * @brief   Override GPIO modes
 *
 * @{
 */
#define HAVE_GPIO_MODE_T
typedef enum {
    GPIO_IN,        /**< input */
    GPIO_IN_PD,     /**< input with pull-down */
    GPIO_IN_PU,     /**< input with pull-up */
    GPIO_OUT,       /**< output */
    GPIO_OD,        /**< open-drain output */
    GPIO_OD_PU,     /**< open-drain output with pull-up */
    GPIO_IN_OUT,    /**< input and output */
    GPIO_IN_OD,     /**< input and open-drain output */
    GPIO_IN_OD_PU   /**< input and open-drain output with pull-up */
} gpio_mode_t;
/** @} */

#endif /* ndef DOXYGEN */
/** @} */

/**
 * @name   ADC configuration
 *
 * ESP32x SoCs integrate two SAR ADCs (ADC1 and ADC2). The bit width of the
 * ADC devices, the number of channels per device and the GPIOs that can be
 * used as ADC channels depend on the respective ESP32x SoC family. For
 * details, see:
 *
 * - \ref esp32_adc_channels_esp32 "ESP32"
 * - \ref esp32_adc_channels_esp32c3 "ESP32-C3"
 * - \ref esp32_adc_channels_esp32s3 "ESP32-S3"
 *
 * #ADC_GPIOS in the board-specific peripheral configuration defines the
 * list of GPIOs that can be used as ADC channels on the board, for example:
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~{.c}
 * #define ADC_GPIOS   { GPIO0, GPIO2, GPIO4 }
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * Thereby the order of the listed GPIOs determines the mapping between the
 * ADC lines of the RIOT and the GPIOs. The maximum number of GPIOs in the
 * list is #ADC_NUMOF_MAX. The board specific configuration of #ADC_GPIOS
 * can be overridden by [Application specific configurations]
 * (#esp32_application_specific_configurations).
 *
 * The number of defined ADC channels #ADC_NUMOF is determined automatically
 * from the #ADC_GPIOS definition.
 *
 * @note As long as the GPIOs listed in #ADC_GPIOS are not initialized as ADC
 *       channels with the #adc_init function, they can be used for other
 *       purposes.
 *
 * With the function #adc_set_attenuation an attenuation of the input signal
 * can be defined separately for each ADC channel.
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~{.c}
 * extern int adc_set_attenuation(adc_t line, adc_attenuation_t atten);
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * This leads to different measurable maximum values for the voltage at the input.
 * The higher the attenuation is, the higher the voltage measured at the input
 * can be.
 *
 * The attenuation can be set to 4 fixed values 0 dB, 2.5/3 dB, 6 dB and
 * 11/12 dB, where 11 dB respectively 12 dB is the default attenuation.
 *
 * <center>
 *
 * Attenuation | Voltage Range     | Symbol
 * -----------:|-------------------|---------------------------
 *       0 dB  | 0 ... 1.1V (Vref) | `ADC_ATTEN_DB_0`
 * 2.5 / 3 dB  | 0 ... 1.5V        | `ADC_ATTEN_DB_2_5`
 *       6 dB  | 0 ... 2.2V        | `ADC_ATTEN_DB_6`
 * 11 / 12 dB  | 0 ... 3.3V        | `ADC_ATTEN_DB_11` (default)
 *
 * </center><br>
 *
 * @note The reference voltage Vref can vary from device to device in the range
 *       of 1.0V and 1.2V.
 *
 * The Vref of a device can be read at a predefined GPIO with the function
 * #adc_line_vref_to_gpio. The results of the ADC input can then be adjusted
 * accordingly.
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~{.c}
 * extern int adc_line_vref_to_gpio(adc_t line, gpio_t gpio);
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 * For the GPIO that can be used with this function, see:
 *
 * - \ref esp32_adc_channels_esp32 "ESP32"
 * - \ref esp32_adc_channels_esp32c3 "ESP32-C3"
 * - \ref esp32_adc_channels_esp32s3 "ESP32-S3"
 *
 * @{
 */

/**
 * @brief  Number of ADC channels that could be used at maximum
 */
#define ADC_NUMOF_MAX   (SOC_ADC_CHANNEL_NUM(0) + SOC_ADC_CHANNEL_NUM(1))

/** @} */

/**
 * @name   DAC configuration
 *
 * Some ESP32x SoCs support 2 DAC lines at predefined GPIOs, depending on the
 * respective ESP32x SoC family. These DACs have a width of 8 bits and produce
 * voltages in the range from 0 V to 3.3 V (VDD_A). The 16 bit DAC values
 * given as parameter of function #dac_set are down-scaled to 8 bit.
 *
 * The GPIOs that can be used as DAC channels for a given board are defined by
 * the `#DAC_GPIOS` macro in the board-specific peripheral configuration.
 * The specified GPIOs in the list must match the predefined GPIOs that can be
 * used as DAC channels on the respective ESP32x SoC.
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~{.c}
 * #define DAC_GPIOS   { GPIO25, GPIO26 }
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * This configuration can be changed by [application-specific configurations]
 * (#esp32_application_specific_configurations).
 *
 * The order of the listed GPIOs determines the mapping between the RIOT's
 * DAC lines and the GPIOs. The maximum number of GPIOs in the list is
 * #DAC_NUMOF_MAX.
 *
 * #DAC_NUMOF is determined automatically from the #DAC_GPIOS definition.
 *
 * @note As long as the GPIOs listed in #DAC_GPIOS are not initialized
 * as DAC channels with the #dac_init function, they can be used for other
 * purposes.
 *
 * DACs are currently only supported for the \ref esp32_dac_channels_esp32
 * "ESP32 SoC" variant.
 *
 * @{
 */

/**
 * @brief  Number of DAC channels that could be used at maximum.
 */
#if defined(SOC_DAC_SUPPORTED) || DOXYGEN
#define DAC_NUMOF_MAX   (SOC_DAC_PERIPH_NUM)
#endif

/** @} */

/**
 * @name   I2C configuration
 *
 * ESP32x SoCs integrate up to two I2C hardware interfaces.
 *
 * The board-specific configuration of the I2C interface I2C_DEV(n) requires
 * the definition of
 *
 * `I2Cn_SPEED`, the bus speed for I2C_DEV(n),
 * `I2Cn_SCL`, the GPIO used as SCL signal for I2C_DEV(n), and
 * `I2Cn_SDA`, the GPIO used as SDA signal for I2C_DEV(n),
 *
 * where `n` can be 0 or 1. If they are not defined, the I2C interface
 * I2C_DEV(n) is not used, for example:
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~{.c}
 * #define I2C0_SPEED  I2C_SPEED_FAST
 * #define I2C0_SCL    GPIO22
 * #define I2C0_SDA    GPIO21
 *
 * #define I2C1_SPEED  I2C_SPEED_NORMAL
 * #define I2C1_SCL    GPIO13
 * #define I2C1_SDA    GPIO16
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * The board-specific pin configuration of I2C interfaces can be changed by
 * [application specific configurations](#esp32_application_specific_configurations)
 * by overriding the according `I2Cn_*` symbols.
 *
 * @note
 * - To ensure that the `I2Cn_*` symbols define the configuration for
 *   I2C_DEV(n), the definition of the configuration of I2C interfaces
 *   I2C_DEV(n) must be in continuous ascending order of `n`.
 *   That is, if I2C_DEV(1) is used by defining the `I2C1_*` symbols,
 *   I2C_DEV(0) must also be used by defining the `I2C0_*` symbols.
 * - The GPIOs listed in the configuration are only initialized as I2C
 *   signals when the `periph_i2c` module is used. Otherwise they are not
 *   allocated and can be used for other purposes.
 * - The same configuration is used when the I2C bit-banging software
 *   implementation is used by enabling module `esp_i2c_sw` (default).
 *
 * The number of used I2C interfaces #I2C_NUMOF is determined automatically
 * from board-specific peripheral definitions of I2C_DEV(n).
 *
 * @{
 */

#ifndef DOXYGEN
/**
 * @brief    Override I2C clock speed values
 *
 * This is required here to have i2c_speed_t defined in this file.
 * @{
 */
#define HAVE_I2C_SPEED_T
typedef enum {
    I2C_SPEED_LOW = 0,      /**< 10 kbit/s */
    I2C_SPEED_NORMAL,       /**< 100 kbit/s */
    I2C_SPEED_FAST,         /**< 400 kbit/s */
    I2C_SPEED_FAST_PLUS,    /**< 1 Mbit/s */
    I2C_SPEED_HIGH,         /**< not supported */
} i2c_speed_t;
/** @} */
#endif /* ndef DOXYGEN */

/**
 * @brief   I2C configuration structure type
 */
typedef struct {
    uint8_t module;         /**< I2C module identifier */
    i2c_speed_t speed;      /**< I2C bus speed */
    gpio_t scl;             /**< GPIO used as SCL pin */
    gpio_t sda;             /**< GPIO used as SDA pin */
    bool scl_pullup;        /**< Pullup enabled for SCL pin */
    bool sda_pullup;        /**< Pullup enabled for SDA pin */
} i2c_conf_t;

/**
 * @brief   Maximum number of I2C interfaces that can be used by board definitions
 */
#define I2C_NUMOF_MAX   (SOC_I2C_NUM)

#define PERIPH_I2C_NEED_READ_REG    /**< Implementation requires #i2c_read_reg */
#define PERIPH_I2C_NEED_READ_REGS   /**< Implementation requires #i2c_read_regs */
#define PERIPH_I2C_NEED_WRITE_REG   /**< Implementation requires #i2c_write_reg */
#define PERIPH_I2C_NEED_WRITE_REGS  /**< Implementation requires #i2c_write_regs */
/** @} */

/**
 * @name   PWM configuration
 *
 * The PWM peripheral driver for ESP32x SoCs uses the LED PWM Controller (LEDC)
 * module for implementation. The LEDC module has either 1 or 2 channel groups
 * with 6 or 8 channels each, where the first channel group comprises the
 * low-speed channels and the second channel group comprises the high-speed
 * channels. The difference is that changes in the configuration of the
 * high-speed channels take effect with the next PWM cycle, while the changes
 * in the configuration of the low-speed channels must be explicitly updated
 * by a trigger.
 *
 * The low-speed channel group always exists while the existence of the
 * high-speed channel group depends on respective ESP32x SoC family.
 *
 * Each channel group has 4 timers which can be used as clock source by the
 * channels of the respective channel group. Thus it would be possible to
 * define a maximum of 4 virtual PWM devices in RIOT per channel group with
 * different frequencies and resolutions. However, regardless of whether the
 * LEDC module of the ESP32x SoC has one or two channel groups, the PWM driver
 * implementation only allows the available channels to be organized into
 * up to 4 virtual PWM devices.
 *
 * The assignment of the available channels to the virtual PWM devices is
 * done in the board-specific peripheral configuration by defining the
 * macros `PWM0_GPIOS`, `PWM1_GPIOS`, `PWM2_GPIOS` and `PWM3_GPIOS` These
 * macros specify the GPIOs that are used as channels for the 4 possible
 * virtual PWM devices PWM_DEV(0) ... PWM_DEV(3) in RIOT, for example:
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~{.c}
 * #define PWM0_GPIOS  { GPIO0, GPIO2, GPIO4, GPIO16, GPIO17 }
 * #define PWM1_GPIOS  { GPIO27, GPIO32, GPIO33 }
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * This configuration can be changed by [application-specific configurations]
 * (#esp32_application_specific_configurations).
 *
 * The mapping of the GPIOs as channels of the available channel groups and
 * channel group timers is organized by the driver automatically as follows:
 *
 * <center>
 *
 * Macro        | 1 Channel Group       | 2 Channel Groups       | Timer
 * -------------|-----------------------|------------------------|---------------
 * `PWM0_GPIOS` | `LEDC_LOW_SPEED_MODE` | `LEDC_LOW_SPEED_MODE`  | `LEDC_TIMER_0`
 * `PWM1_GPIOS` | `LEDC_LOW_SPEED_MODE` | `LEDC_HIGH_SPEED_MODE` | `LEDC_TIMER_1`
 * `PWM2_GPIOS` | `LEDC_LOW_SPEED_MODE` | `LEDC_LOW_SPEED_MODE`  | `LEDC_TIMER_2`
 * `PWM3_GPIOS` | `LEDC_LOW_SPEED_MODE` | `LEDC_HIGH_SPEED_MODE` | `LEDC_TIMER_3`
 *
 * </center>
 *
 * For example, if the LEDC module of the ESP32x SoC has two channel groups,
 * two virtual PWM devices with 2 x 6 (or 8) channels could be used by defining
 * 'PWM0_GPIOS' and 'PWM1_GPIOS' with 6 (or 8) GPIOs each.
 *
 * The number of used PWM devices #PWM_NUMOF is determined automatically from the
 * definition of `PWM0_GPIOS`, `PWM1_GPIOS`, `PWM2_GPIOS` and `PWM3_GPIOS`.
 *
 * @note
 * - The total number of channels defined for a channel group must not exceed
 *   #PWM_CH_NUMOF_MAX
 * - The definition of `PWM0_GPIOS`, `PWM1_GPIOS`, `PWM2_GPIOS` and
 *   `PWM3_GPIOS` can be omitted. However, to ensure that `PWMn_GPIOS` defines
 *   the configuration for PWM_DEV(n), the PWM channels must be defined in
 *   continuous ascending order from `n`. That means, if `PWM1_GPIOS` is
 *   defined, `PWM0_GPIOS` must be defined before, and so on. So a minimal
 *   configuration would define all channels by `PWM0_GPIOS` as PWM_DEV(0).
 * - The order of the GPIOs in these macros determines the mapping between
 *   RIOT's PWM channels and the GPIOs.
 * - As long as the GPIOs listed in `PWM0_GPIOS`, `PWM1_GPIOS`,
 *   `PWM2_GPIOS` and `PWM3_GPIOS` are not initialized as PWM channels with
 *   the #pwm_init function, they can be used for other purposes.
 *
 * @{
 */

/**
 * @brief   PWM configuration structure type
 *
 * The implementation of the PWM peripheral driver uses the LED PWM Controller
 * (LEDC) module of the ESP32x SoC. The LEDC module has up to 2 channel groups
 * with 6 or 8 channels each, which can use one of 4 timers.
 *
 * Based on these maximum 2 channel groups with 6 or 8 channels each and 4
 * timers, up to 4 PWM devices can be configured in RIOT. The configuration
 * structure defines static parameters for each virtual PWM device, i.e.
 * the channel group used, the timer used, the number of channels used and
 * the GPIOs assigned to the channels. The number of channels used by a PWM
 * device corresponds to the number of GPIOs assigned to this PWM device.
 */
typedef struct {
    uint8_t module;         /**< LEDC module identifier */
    ledc_mode_t group;      /**< LEDC channel group used (low/high speed) */
    ledc_timer_t timer;     /**< LEDC timer used by this device */
    uint8_t ch_numof;       /**< Number of channels used by this device */
    const gpio_t *gpios;    /**< GPIOs used as channels of this device */
} pwm_config_t;

/**
 * @brief   Maximum number of PWM devices
 */
#define PWM_NUMOF_MAX       (4)

/**
 * @brief   Maximum number of channels per PWM device.
 */
#define PWM_CH_NUMOF_MAX    (SOC_LEDC_CHANNEL_NUM)

/** @} */

/**
 * @name    RNG configuration
 * @{
 */

/**
 * @brief   The address of the register for accessing the hardware RNG.
 */
#define RNG_DATA_REG_ADDR   (WDEV_RND_REG)
/** @} */

/**
 * @name    RTT and RTC configuration
 * @{
 */

/**
 * @brief   RTT frequency definition
 *
 * The RTT frequency is always 32.768 kHz even if no external crystal is
 * connected. In this case the RTT value counted with the internal 150 kHz
 * RC oscillator is converted to a value for an RTT with 32.768 kHz.
 */
#define RTT_FREQUENCY       (32768UL)

/**
 * @brief   RTT is a 32-bit counter
 */
#define RTT_MAX_VALUE       (0xFFFFFFFFUL)

/** @} */

/**
 * @name   SPI configuration
 *
 * ESP32x SoCs have up to four SPI controllers dependent on the specific ESP32x
 * SoC variant (family):
 *
 * - Controller SPI0 is reserved for caching external memory like Flash
 * - Controller SPI1 is reserved for external memories like PSRAM
 * - Controller SPI2 can be used as general purpose SPI (GPSPI)
 * - Controller SPI3 can be used as general purpose SPI (GPSPI)
 *
 * The controllers SPI0 and SPI1 share the same bus signals and can only
 * operate in memory mode on most ESP32x SoC variants. Therefore, depending on
 * the specific ESP32x SoC family, a maximum of two SPI controllers can be used
 * as peripheral interfaces:
 *
 * - Controller SPI2 is identified by `SPI2_HOST` (also called FSPI or HSPI)
 * - Controller SPI3 is identified by `SPI3_HOST` (also called VSPI)
 *
 * In former ESP-IDF versions, SPI interfaces were identified by the alias
 * names `FSPI`, `HSPI` and `VSPI`, which are sometimes also used in data
 * sheets. These alias names have been declared obsolete in ESP-IDF. For
 * source code compatibility reasons these alias names are defined here.
 *
 * SPI interfaces could be used in quad SPI mode, but RIOT's low level
 * device driver doesn't support it.
 *
 * The board-specific configuration of the SPI interface SPI_DEV(n) requires
 * the definition of
 *
 * - `SPIn_CTRL`, the SPI controller (`SPI_HOST2`/`SPI_HOST3`) used for SPI_DEV(n),
 * - `SPIn_SCK`, the GPIO used as clock signal used for SPI_DEV(n)
 * - `SPIn_MISO`, the GPIO used as MISO signal used for SPI_DEV(n)
 * - `SPIn_MOSI`, the GPIO used as MOSI signal used for SPI_DEV(n), and
 * - `SPIn_CS0`, the GPIO used as CS signal for SPI_DEV(n) when the `cs`
 *   parameter in #spi_acquire is #GPIO_UNDEF,
 *
 * where `n` can be 0 and 1. If they are not defined, the according SPI
 * interface SPI_DEV(n) is not used, for example:
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~{.c}
 * #define SPI0_CTRL   SPI3_HOST   // VSPI could also be used on ESP32 variant
 * #define SPI0_SCK    GPIO18      // SCK  signal
 * #define SPI0_MISO   GPIO19      // MISO signal
 * #define SPI0_MOSI   GPIO23      // MOSI signal
 * #define SPI0_CS0    GPIO5       // CS0  signal
 *
 * #define SPI1_CTRL   SPI2_HOST   // HSPI could also be used here on ESP32 variant
 * #define SPI1_SCK    GPIO14      // SCK  Camera
 * #define SPI1_MISO   GPIO12      // MISO Camera
 * #define SPI1_MOSI   GPIO13      // MOSI Camera
 * #define SPI1_CS0    GPIO15      // CS0  Camera
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * The pin configuration of SPI interfaces can be changed by
 * [application specific configurations](#esp32_application_specific_configurations)
 * by overriding the according `SPIn_*` symbols.
 *
 * @note
 * - To ensure that the `SPIn_*` symbols define the configuration for
 *   SPI_DEV(n), the definition of the configuration of SPI interfaces
 *   SPI_DEV(n) must be in continuous ascending order of `n`.
 *   That is, if SPI_DEV(1) is used by defining the `SPI1_*` symbols,
 *   SPI_DEV(0) must also be used by defining the `SPI0_*` symbols.
 * - The order in which the available interfaces `SPI2_HOST` (alias `HSPI` or
 *   `FSPI`) and `SPI3_HOST` (alias `VPSI` or `HSPI`) are assigned doesn't matter.
 * - The GPIOs listed in the configuration are only initialized as SPI
 *   signals when the `periph_spi` module is used. Otherwise they are not
 *   allocated and can be used for other purposes.
 *
 * #SPI_NUMOF is determined automatically from the board-specific peripheral
 * configuration for SPI_DEV(n).
 *
 * @{
 */

#ifndef DOXYGEN
/**
 * @brief    Override SPI clock speed values
 * @{
 */
#define HAVE_SPI_CLK_T
typedef enum {
    SPI_CLK_100KHZ = 100000,            /**< drive the SPI bus with 100KHz */
    SPI_CLK_400KHZ = 400000,            /**< drive the SPI bus with 400KHz */
    SPI_CLK_1MHZ   = 1000000,           /**< drive the SPI bus with 1MHz */
    SPI_CLK_5MHZ   = 5000000,           /**< drive the SPI bus with 5MHz */
    SPI_CLK_10MHZ  = 10000000           /**< drive the SPI bus with 10MHz */
} spi_clk_t;
/** @} */
#endif /* !DOXYGEN */

/**
 * @brief   Mapping of SPI controller type for source code compatibility
 */
typedef spi_host_device_t spi_ctrl_t;

/*
 * In former ESP-IDF versions, SPI interfaces were identified by the alias
 * names `FSPI`, `HSPI` and `VSPI`, which are sometimes also used in data
 * sheets. These alias names have been declared obsolete in ESP-IDF. For
 * source code compatibility reasons these alias names are defined here.
 */
#if defined(CPU_FAM_ESP32)
#define HSPI    SPI2_HOST   /**< Alias name for SPI2_HOST as used in former ESP-IDF versions */
#define VSPI    SPI3_HOST   /**< Alias name for SPI3_HOST as used in former ESP-IDF versions */
#elif defined(CPU_FAM_ESP32S2)
#define FSPI    SPI2_HOST   /**< Alias name for SPI2_HOST as used in former ESP-IDF versions */
#define HSPI    SPI3_HOST   /**< Alias name for SPI3_HOST as used in former ESP-IDF versions */
#else
#define FSPI    SPI2_HOST   /**< Alias name for SPI2_HOST as used in former ESP-IDF versions */
#endif

/**
 * @brief   SPI configuration structure type
 */
typedef struct {
    spi_ctrl_t ctrl;        /**< SPI controller used for the interface */
    gpio_t sck;             /**< GPIO used as SCK pin */
    gpio_t mosi;            /**< GPIO used as MOSI pin */
    gpio_t miso;            /**< GPIO used as MISO pin */
    gpio_t cs;              /**< GPIO used as CS0 pin */
} spi_conf_t;

/**
 * @brief   Maximum number of SPI interfaces that can be used by board definitions
 */
#define SPI_NUMOF_MAX   (SOC_SPI_PERIPH_NUM - 1)

#define PERIPH_SPI_NEEDS_TRANSFER_BYTE  /**< requires function spi_transfer_byte */
#define PERIPH_SPI_NEEDS_TRANSFER_REG   /**< requires function spi_transfer_reg */
#define PERIPH_SPI_NEEDS_TRANSFER_REGS  /**< requires function spi_transfer_regs */
/** @} */

/**
 * @name   Timer configuration depending on which implementation is used
 *
 * There are two different implementations for hardware timers.
 *
 * - **Timer Module implementation** Depending on the ESP32x SoC variant
 *   (family) it provides up to 4 high speed timers, where 1 timer is used for
 *   system time. The remaining timer devices with **1 channel** each can be
 *   used as RIOT timer devices with a clock rate of 1 MHz.
 * - **Counter implementation** Dependent on the ESP32x SoC variant (family),
 *   the MCU has up to 3 CCOMPARE (cycle compare) registers. Two of them can be
 *   used to implement up to **2 timer devices** with **1 channel** each and a
 *   clock rate of 1 MHz. This is a feature of Xtensa-based ESP32x SoC variants.
 *
 * By default, the timer module is used. To use the counter implementation, add
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 * USEMODULE += esp_hw_counter
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 * to application's makefile.
 *
 * Timers are MCU built-in features and not board-specific. There is nothing to
 * be configured.
 * @{
 */

#ifndef MODULE_ESP_HW_COUNTER
/**
 * @brief Hardware timer modules are used for timer implementation (default)
 *
 * Since one timer is used for the system time, there is one timer less than
 * the total number of timers.
 */
#define TIMER_NUMOF         (SOC_TIMER_GROUP_TOTAL_TIMERS - 1)
#define TIMER_CHANNEL_NUMOF (1)
#endif

/** Timer group used for system time */
#define TIMER_SYSTEM_GROUP      TIMER_GROUP_0
/** Index of the timer in the timer timer group used for system time */
#define TIMER_SYSTEM_INDEX      TIMER_0
/** System time interrupt source */
#define TIMER_SYSTEM_INT_SRC    ETS_TG0_T0_LEVEL_INTR_SOURCE

/** @} */

/**
 * @brief   Prevent shared timer functions from being used
 */
#define PERIPH_TIMER_PROVIDES_SET

/**
 * @name   UART configuration
 *
 * ESP32x SoCs integrate up to three UART devices, depending on the specific
 * ESP32x SoC variant (family).
 *
 * The pin configuration of the UART device UART_DEV(n) is defined in the
 * board-specific peripheral configuration by
 *
 * - `UARTn_TXD`, the GPIO used as TxD signal for UART_DEV(n), and
 * - `UARTn_RXD`, the GPIO used as RxD signal for UART_DEV(n),
 *
 * where `n` can be in range of 0 and UART_NUMOF_MAX-1. If they are not defined,
 * the according UART interface UART_DEV(n) is not used, for example:
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~{.c}
 * #define UART1_TX    GPIO10  // TxD signal of UART_DEV(1)
 * #define UART1_RX    GPIO9   // RxD signal of UART_DEV(1)
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * The pin configuration of UART interfaces can be changed by
 * [application specific configurations](#esp32_application_specific_configurations)
 * by overriding the according `UARTn_*` symbols.
 *
 * @note To ensure that the `UARTn_*` symbols define the configuration for
 *       UART_DEV(n), the configuration of the UART interfaces UART_DEV(n)
 *       must be in continuous ascending order of `n`. That is, if UART_DEV(1)
 *       is to be used by defining the `UART1_*` symbols, UART_DEV(0) must also
 *       be used by defining the `UART0_*` symbols, and if UART_DEV(2)
 *       is to be used by defining the `UART2_*` symbols, UART_DEV(0) and
 *       UART_DEV(1) must also be used by defining the `UART0_*` and
 *       `UART1_*` symbols
 *
 * #UART_NUMOF is determined automatically from the board-specific peripheral
 * configuration for UART_DEV(n).
 *
 * UART_DEV(0) has usually a fixed pin configuration that is used by all
 * ESP32x boards as standard configuration for the console. The GPIOs
 * used for UART_DEV(0) depend on the ESP32x SoC family.
 *
 * @{
 */

/**
 * @brief   UART configuration structure type
 */
typedef struct {
    gpio_t txd;             /**< GPIO used as TxD pin */
    gpio_t rxd;             /**< GPIO used as RxD pin */
} uart_conf_t;

/**
 * @brief   Maximum number of UART interfaces
 */
#define UART_NUMOF_MAX  (SOC_UART_NUM)
/** @} */

#ifdef __cplusplus
}
#endif

/**
 * @brief   Include ESP32x family specific peripheral configuration
 */
#if defined(CPU_FAM_ESP32)
#include "periph_cpu_esp32.h"
#elif defined(CPU_FAM_ESP32C3)
#include "periph_cpu_esp32c3.h"
#elif defined(CPU_FAM_ESP32S2)
#include "periph_cpu_esp32s2.h"
#elif defined(CPU_FAM_ESP32S3)
#include "periph_cpu_esp32s3.h"
#else
#error "ESP32x family implementation missing"
#endif

#ifdef MODULE_PERIPH_CAN
#include "can_esp.h"
#endif

#endif /* PERIPH_CPU_H */
/** @} */
