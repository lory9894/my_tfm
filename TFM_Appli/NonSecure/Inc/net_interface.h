/**
  **********************************************************************************************************************
  * @file    net_interface.h
  * @author  MCD Application Team
  * @brief   Header file for net_interface.c
  **********************************************************************************************************************
  * @attention
  *
  * Copyright (c) 2021 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  **********************************************************************************************************************
  */

/* Define to prevent recursive inclusion -----------------------------------------------------------------------------*/
#ifndef NET_INTERFACE_H
#define NET_INTERFACE_H

#ifdef __cplusplus
extern "C" {
#endif

/* Includes ----------------------------------------------------------------------------------------------------------*/
#include "net_connect.h"
#include "net_wifi.h"
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>

typedef struct
{
  const char *ssid;
  const char *pwd;
} ap_t;

void NetWifiGetDefaultStation(net_wifi_credentials_t *WifiCreds, const ap_t net_wifi_registred_hotspot[]);
net_if_handle_t *NetInterfaceOn(net_if_driver_init_func driver_init, net_if_notify_func notify_func);
void NetInterfaceConnect(net_if_handle_t *netif, bool dhcp_mode, void *credential, net_wifi_mode_t mode);
void NetInterfaceDisconnect(net_if_handle_t *netif);
void NetInterfaceOff(net_if_handle_t *netif);
int32_t scan_cmd(int32_t argc, char **argv);


/* The network interface in use. */
extern net_if_handle_t *Netif;

#ifdef __cplusplus
}
#endif

#endif /* NET_INTERFACE_H */
