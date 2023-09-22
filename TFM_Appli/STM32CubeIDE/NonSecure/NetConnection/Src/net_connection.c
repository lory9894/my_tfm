/*
 * net_connection.c
 *
 *  Created on: Sep 14, 2023
 *      Author: lorenzo
 */
#include <stdio.h>
#include "mx_wifi.h"
#include "io_pattern/mx_wifi_io.h"
#include "stm32u5xx_hal_spi.h"
#include "net_connection.h"
#include "net_status.h"

/* MxChip WiFi SPI handle declaration */
SPI_HandleTypeDef Wifi_SPIHandle;

/* Private function declaration ---------------------------------------------------------------------------------------*/
void prova(void);
static void Wifi_IO_Init(void);
static WebServer_StatusTypeDef Wifi_SPI_Config(void);
/* Function implementation---------------------------------------------------------------------------------------*/

void prova(void){
	printf("include funziona\r\n");
}


static void Wifi_IO_Init(void)
{
  GPIO_InitTypeDef GPIO_InitStruct = {0};

  /* GPIO Ports Clock Enable */
  __HAL_RCC_GPIOG_CLK_ENABLE();
  __HAL_RCC_GPIOC_CLK_ENABLE();
  __HAL_RCC_GPIOD_CLK_ENABLE();
  __HAL_RCC_GPIOA_CLK_ENABLE();
  __HAL_RCC_GPIOB_CLK_ENABLE();
  __HAL_RCC_GPIOF_CLK_ENABLE();

  /*Configure GPIO pin Output Level */
  HAL_GPIO_WritePin(MXCHIP_RESET_GPIO_Port, MXCHIP_RESET_Pin, GPIO_PIN_RESET);

  /*Configure GPIO pin Output Level */
  HAL_GPIO_WritePin(GPIOD, GPIO_PIN_14, GPIO_PIN_RESET);

  /*Configure GPIO pin Output Level */
  HAL_GPIO_WritePin(MXCHIP_NSS_GPIO_Port, MXCHIP_NSS_Pin, GPIO_PIN_SET);

  /*Configure GPIO pin : MXCHIP_FLOW_Pin */
  GPIO_InitStruct.Pin = MXCHIP_FLOW_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_IT_RISING;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  HAL_GPIO_Init(MXCHIP_FLOW_GPIO_Port, &GPIO_InitStruct);

  /*Configure GPIO pin : MXCHIP_RESET_Pin */
  GPIO_InitStruct.Pin = MXCHIP_RESET_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  HAL_GPIO_Init(MXCHIP_RESET_GPIO_Port, &GPIO_InitStruct);

  /*Configure GPIO pin : PD14 */
  GPIO_InitStruct.Pin = GPIO_PIN_14;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  HAL_GPIO_Init(GPIOD, &GPIO_InitStruct);

  /*Configure GPIO pin : MXCHIP_NSS_Pin */
  GPIO_InitStruct.Pin = MXCHIP_NSS_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  HAL_GPIO_Init(MXCHIP_NSS_GPIO_Port, &GPIO_InitStruct);

  /*Configure GPIO pin : MXCHIP_NOTIFY_Pin */
  GPIO_InitStruct.Pin = MXCHIP_NOTIFY_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_IT_RISING;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  HAL_GPIO_Init(MXCHIP_NOTIFY_GPIO_Port, &GPIO_InitStruct);

  /* EXTI interrupt init*/
  HAL_NVIC_SetPriority(EXTI14_IRQn, 5, 0);
  HAL_NVIC_EnableIRQ(EXTI14_IRQn);

  HAL_NVIC_SetPriority(EXTI15_IRQn, 5, 0);
  HAL_NVIC_EnableIRQ(EXTI15_IRQn);
}

static WebServer_StatusTypeDef Wifi_SPI_Config(void)
{
  /* Set SPI instance */
  Wifi_SPIHandle.Instance                        = SPI2;

  /* Set parameter to be configured */
  Wifi_SPIHandle.Init.Mode                       = SPI_MODE_MASTER;
  Wifi_SPIHandle.Init.Direction                  = SPI_DIRECTION_2LINES;
  Wifi_SPIHandle.Init.DataSize                   = SPI_DATASIZE_8BIT;
  Wifi_SPIHandle.Init.CLKPolarity                = SPI_POLARITY_LOW;
  Wifi_SPIHandle.Init.CLKPhase                   = SPI_PHASE_1EDGE;
  Wifi_SPIHandle.Init.NSS                        = SPI_NSS_SOFT;
  Wifi_SPIHandle.Init.BaudRatePrescaler          = SPI_BAUDRATEPRESCALER_8;
  Wifi_SPIHandle.Init.FirstBit                   = SPI_FIRSTBIT_MSB;
  Wifi_SPIHandle.Init.TIMode                     = SPI_TIMODE_DISABLE;
  Wifi_SPIHandle.Init.CRCCalculation             = SPI_CRCCALCULATION_DISABLE;
  Wifi_SPIHandle.Init.CRCPolynomial              = 0x7;
  Wifi_SPIHandle.Init.NSSPMode                   = SPI_NSS_PULSE_DISABLE;
  Wifi_SPIHandle.Init.NSSPolarity                = SPI_NSS_POLARITY_LOW;
  Wifi_SPIHandle.Init.FifoThreshold              = SPI_FIFO_THRESHOLD_01DATA;
  Wifi_SPIHandle.Init.MasterSSIdleness           = SPI_MASTER_SS_IDLENESS_00CYCLE;
  Wifi_SPIHandle.Init.MasterInterDataIdleness    = SPI_MASTER_INTERDATA_IDLENESS_00CYCLE;
  Wifi_SPIHandle.Init.MasterReceiverAutoSusp     = SPI_MASTER_RX_AUTOSUSP_DISABLE;
  Wifi_SPIHandle.Init.MasterKeepIOState          = SPI_MASTER_KEEP_IO_STATE_DISABLE;
  Wifi_SPIHandle.Init.IOSwap                     = SPI_IO_SWAP_DISABLE;
  Wifi_SPIHandle.Init.ReadyMasterManagement      = SPI_RDY_MASTER_MANAGEMENT_INTERNALLY;
  Wifi_SPIHandle.Init.ReadyPolarity              = SPI_RDY_POLARITY_HIGH;

  /* SPI initialization */
  if (HAL_SPI_Init(&Wifi_SPIHandle) != HAL_OK)
  {
    return PERIPH_ERROR;
  }

  return WEBSERVER_OK;
}

WebServer_StatusTypeDef webserver_wifi_init(void)
{
  /* WiFi IO configuration */
  Wifi_IO_Init();

  /* WiFi SPI initialization and configuration */
  WebServer_StatusTypeDef status = Wifi_SPI_Config();
  if (status != WEBSERVER_OK)
  {
	printf("error during wifi initialization: %i \r\n", status);
    return WIFI_ERROR;
  }

  return WEBSERVER_OK;
}
