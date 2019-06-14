/*
 * Copyright (C) 2018 Mesotic SAS
 *
 * This file is subject to the terms and conditions of the GNU Lesser General
 * Public License v2.1. See the file LICENSE in the top level directory for
 * more details.
 */

#ifndef USB_CDC_ACM_H
#define USB_CDC_ACM_H

#ifdef __cplusplus
extern "c" {
#endif

#define USB_SETUP_REQ_SET_LINE_CODING           0x20
#define USB_SETUP_REQ_GET_LINE_CODING           0x21
#define USB_SETUP_REQ_SET_CONTROL_LINE_STATE    0x22

#define USB_CDC_ACM_CONTROL_LINE_DTE            0x01 /**< DTE (PC) is present */
#define USB_CDC_ACM_CONTROL_LINE_CARRIER        0x02 /**< Carrier control for half duplex */

#ifdef __cplusplus
}
#endif

#endif /* USB_CDC_ACM_H */
/** @} */
