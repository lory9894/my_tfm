/* Define to prevent recursive inclusion -------------------------------------*/
#ifndef NET_CONNECTION_H
#define NET_CONNECTION_H

/* Includes ------------------------------------------------------------------*/
#include <stdio.h>
#include "net_status.h"
#include "stm32u5xx_hal_spi.h"

/* Exported types ------------------------------------------------------------*/
/* Exported constants --------------------------------------------------------*/
#define MXCHIP_SPI              Wifi_SPIHandle
#define MXCHIP_FLOW_Pin         GPIO_PIN_15
#define MXCHIP_FLOW_GPIO_Port   GPIOG
#define MXCHIP_FLOW_EXTI_IRQn   EXTI15_IRQn
#define MXCHIP_RESET_Pin        GPIO_PIN_15
#define MXCHIP_RESET_GPIO_Port  GPIOF
#define MXCHIP_NSS_Pin          GPIO_PIN_12
#define MXCHIP_NSS_GPIO_Port    GPIOB
#define MXCHIP_NOTIFY_Pin       GPIO_PIN_14
#define MXCHIP_NOTIFY_GPIO_Port GPIOD
#define MXCHIP_NOTIFY_EXTI_IRQn EXTI14_IRQn
/* Exported macros -----------------------------------------------------------*/
/* Exported functions --------------------------------------------------------*/
#ifdef __cplusplus
extern "C" {
#endif

void prova(void);
WebServer_StatusTypeDef webserver_wifi_init(void);


#ifdef __cplusplus
}
#endif
/* Exported variables --------------------------------------------------------*/
#endif /* NET_CONNECTION_H */
