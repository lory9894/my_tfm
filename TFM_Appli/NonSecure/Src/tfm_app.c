/**
  ******************************************************************************
  * @file    tfm_app.c
  * @author  MCD Application Team
  * @brief   TFM application examples module.
  *          This file provides examples of PSA API usages.
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2021 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */

/* Includes ------------------------------------------------------------------*/
#include <string.h>
#include "tfm_app.h"
#include "psa/error.h"
#include "crypto_tests_common.h"
#include "psa/protected_storage.h"
#include "q_useful_buf.h"
#include "psa/initial_attestation.h"
#include "psa/internal_trusted_storage.h"
#include "psa/crypto_sizes.h"
#include "com.h"
#include "region_defs.h"


/** @defgroup  TFM_App_Private_Defines Private Defines
  * @{
  */

/* Private define  ---------------------------------------------------------*/
#define TEST_UID      2U
#define TEST_DATA          "TRUSTEDFIRMWARE_FOR_STM32"
#define TEST_DATA_SIZE     (sizeof(TEST_DATA) - 1)
#define TEST_READ_DATA     "############################################"

#define KEY_ID        1U

#define TOKEN_TEST_NONCE_BYTES \
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
#define TOKEN_TEST_VALUE_NONCE \
  (struct q_useful_buf_c) {\
    (uint8_t[]){TOKEN_TEST_NONCE_BYTES},\
    64\
  }

#define TOKEN_OPT_NORMAL_CIRCUIT_SIGN 0x0U

/**
  * @}
  */

static psa_key_handle_t key_handle = {0};


/** @defgroup  TFM_App_Private_Functions Private Functions
  * @{
  */
static void tfm_app_print_menu(void);
static void tfm_ps_set_uid(struct test_result_t *ret);
static void tfm_ps_remove_uid(struct test_result_t *ret);
static void tfm_ps_read_uid(struct test_result_t *ret);
static void tfm_its_set_uid(struct test_result_t *ret);
static void tfm_its_remove_uid(struct test_result_t *ret);
static void tfm_its_read_uid(struct test_result_t *ret);
static void tfm_crypto_persistent_key_import(struct test_result_t *ret);
static void tfm_crypto_persistent_key_destroy(struct test_result_t *ret);
static void tfm_crypto_persistent_key_export(struct test_result_t *ret);
static void tfm_crypto_persistent_key_generate(struct test_result_t *ret);
static void tfm_crypto_persistent_key_generate_simm(struct test_result_t *ret);
static void tfm_crypto_persistent_key_print(struct test_result_t *ret);
static void tfm_crypto_persistent_encrypt(struct test_result_t *ret);
static void tfm_crypto_persistent_encrypt_simm(struct test_result_t *ret);
#ifdef PSA_USE_SE_ST
static void print_data(uint8_t *data, size_t size, size_t line);
static void tfm_stsafe_test(struct test_result_t *ret);
#endif

void dump_eat_token(struct q_useful_buf_c *token);
static void tfm_eat_test_circuit_sig(uint32_t encode_options, struct test_result_t *ret);
static  psa_status_t token_main_alt(uint32_t option_flags,
                                             struct q_useful_buf_c nonce,
                                             struct q_useful_buf buffer,
                                             struct q_useful_buf_c *completed_token);

/**
  * @}
  */

/** @defgroup  TFM_App_Exported_Functions Exported Functions
  * @{
  */

/**
  * @brief  Display the TFM App TEST Main Menu choices on HyperTerminal
  * @param  None.
  * @retval None.
  */
void tfm_app_menu(void)
{
  uint8_t key = 0;
  uint8_t exit = 0;
  uint8_t tests_executed;
  uint8_t tests_success;
  struct test_result_t ret;

  tfm_app_print_menu();

  while (exit == 0U)
  {
    key = 0U;

    INVOKE_SCHEDULE_NEEDS();

    /* Clean the user input path */
    COM_Flush();
    /* Receive key */
    if (COM_Receive(&key, 1U, COM_UART_TIMEOUT_MAX) == HAL_OK)
    {
      switch (key)
      {


        case 'i' :
          ret.val = TEST_FAILED;
          tfm_crypto_persistent_key_import(&ret);
          printf("Persistent key import test %s\r\n", (ret.val == TEST_PASSED) ? "SUCCESSFUL" : "FAILED");
          tfm_app_print_menu();
          break;

        case 'e' :
          ret.val = TEST_FAILED;
          tfm_crypto_persistent_key_export(&ret);
          printf("Persistent key export test %s\r\n", (ret.val == TEST_PASSED) ? "SUCCESSFUL" : "FAILED");
          tfm_app_print_menu();
          break;
        case 'd' :
          ret.val = TEST_FAILED;
          tfm_crypto_persistent_key_destroy(&ret);
          printf("Persistent key destroy test %s\r\n", (ret.val == TEST_PASSED) ? "SUCCESSFUL" : "FAILED");
          tfm_app_print_menu();
          break;
        case 'g':
  		  ret.val = TEST_FAILED;
          tfm_crypto_persistent_key_generate(&ret);
		  printf("Persistent key generation test %s\r\n", (ret.val == TEST_PASSED) ? "SUCCESSFUL" : "FAILED");
		  tfm_app_print_menu();
		  break;
        case 'h':
  		  ret.val = TEST_FAILED;
          tfm_crypto_persistent_key_generate_simm(&ret);
		  printf("Persistent key generation test %s\r\n", (ret.val == TEST_PASSED) ? "SUCCESSFUL" : "FAILED");
		  tfm_app_print_menu();
		break;
		case 'p' :
          ret.val = TEST_FAILED;
          tfm_crypto_persistent_key_print(&ret);
          printf("Persistent key print test %s\r\n", (ret.val == TEST_PASSED) ? "SUCCESSFUL" : "FAILED");
          tfm_app_print_menu();
        break;
        case 'l' :
    	  ret.val = TEST_FAILED;
          tfm_crypto_persistent_encrypt(&ret);
          printf("Persistent key encrypt test \r\n");
          tfm_app_print_menu();
        break;
        case 'm' :
          tfm_crypto_persistent_encrypt_simm(&ret);
          printf("Persistent key encrypt test \r\n");
          tfm_app_print_menu();
        break;
#ifdef PSA_USE_SE_ST
        case 's' :
          ret.val = TEST_FAILED;
          tfm_stsafe_test(&ret);
          printf("STSAFE Test %s\r\n", (ret.val == TEST_PASSED) ? "SUCCESSFUL" : "FAILED");
          tfm_app_print_menu();
          break;
#endif
        case 'x':
          exit = 1;
          break;

        default:
          printf("Invalid Number !\r");
          tfm_app_print_menu();
          break;
      }
    }
  }
}
/**
  * @}
  */

/** @addtogroup  TFM_App_Private_Functions
  * @{
  */

/**
  * @brief  Display the TEST TFM App Menu choices on HyperTerminal
  * @param  None.
  * @retval None.
  */
static void tfm_app_print_menu(void)
{
  printf("\r\n======================= TFM Examples Menu ===========================\r\n\n");
  printf("  TFM - Test Persistent key import                 --------------------- i\r\n\n");
  printf("  TFM - Test Persistent key export                 --------------------- e\r\n\n");
  printf("  TFM - Test Persistent key destroy                --------------------- d\r\n\n");
  printf("  TFM - Test Persistent key generation             --------------------- g\r\n\n");
  printf("  TFM - Test Persistent simmetric key generation   --------------------- h\r\n\n");
  printf("  TFM - Test Persistent key print                  --------------------- p\r\n\n");
  printf("  TFM - Test Persistent key encryption             --------------------- l\r\n\n");
  printf("  TFM - Test Persistent simmetric key encryption   --------------------- m\r\n\n");
#ifdef PSA_USE_SE_ST
  printf("  TFM - Test STSAFE                                --------------------- s\r\n\n");
#endif
  printf("  Exit TFM Examples Menu                           --------------------- x\r\n\n");
}
/**
  * @brief  Write in PS a TEST UID
  * @param  struct test_result_t
  * @retval None
  */
static void tfm_ps_set_uid(struct test_result_t *ret)
{
  psa_status_t status;
  const psa_storage_uid_t  uid = TEST_UID;
  const psa_storage_create_flags_t flags = PSA_STORAGE_FLAG_NONE;
  const uint32_t write_len = TEST_DATA_SIZE;
  const uint8_t write_data[] = TEST_DATA;
  /* Set a UIDtime */
  status = psa_ps_set(uid, write_len, write_data, flags);
  ret->val = status == PSA_SUCCESS ? TEST_PASSED : TEST_FAILED;
  return;
}

/**
  * @brief  Remove in PS a TEST UID
  * @param  struct test_result_t
  * @retval None
  */
static void tfm_ps_remove_uid(struct test_result_t *ret)
{
  psa_status_t status;
  const psa_storage_uid_t uid = TEST_UID;
  /* remove UID */
  status = psa_ps_remove(uid);
  ret->val = status == PSA_SUCCESS ? TEST_PASSED : TEST_FAILED;
  return ;
}

/**
  * @brief  Read in PS a TEST UID and compare with expected value
  * @param  struct test_result_t
  * @retval None
  */
static void tfm_ps_read_uid(struct test_result_t *ret)
{
  psa_status_t status;
  const psa_storage_uid_t uid = TEST_UID;
  size_t data_len;
  uint8_t read_data[] = TEST_READ_DATA ;
  uint8_t expected_data[] = TEST_DATA;
  /* read UID */
  status = psa_ps_get(uid, 0, TEST_DATA_SIZE, read_data, &data_len);
  if ((status == PSA_SUCCESS) && (!memcmp(read_data, expected_data, TEST_DATA_SIZE)))
  {
    ret->val = TEST_PASSED;
  }
  else
  {
    ret->val = TEST_FAILED;
  }
  return;
}

/**
  * @brief  Write in ITS a TEST UID
  * @param  struct test_result_t
  * @retval None
  */
static void tfm_its_set_uid(struct test_result_t *ret)
{
  psa_status_t status;
  const psa_storage_uid_t uid = TEST_UID;
  const psa_storage_create_flags_t flags = PSA_STORAGE_FLAG_NONE;
  const uint32_t write_len = TEST_DATA_SIZE;
  const uint8_t write_data[] = TEST_DATA;
  /* Set a UIDtime */
  status = psa_its_set(uid, write_len, write_data, flags);
  ret->val = status == PSA_SUCCESS ? TEST_PASSED : TEST_FAILED;
  return;
}

/**
  * @brief  Remove in ITS a TEST UID
  * @param  struct test_result_t
  * @retval None
  */
static void tfm_its_remove_uid(struct test_result_t *ret)
{
  psa_status_t status;
  const psa_storage_uid_t uid = TEST_UID;
  /* remove UID */
  status = psa_its_remove(uid);
  ret->val = status == PSA_SUCCESS ? TEST_PASSED : TEST_FAILED;
  return ;
}

/**
  * @brief  Read in ITS a TEST UID and compare with expected value
  * @param  struct test_result_t
  * @retval None
  */
static void tfm_its_read_uid(struct test_result_t *ret)
{
  psa_status_t status;
  const psa_storage_uid_t uid = TEST_UID;
  size_t data_len;
  uint8_t read_data[] = TEST_READ_DATA ;
  uint8_t expected_data[] = TEST_DATA;
  /* read UID */
  status = psa_its_get(uid, 0, TEST_DATA_SIZE, read_data, &data_len);
  if ((status == PSA_SUCCESS) && (data_len == TEST_DATA_SIZE)
      && (!memcmp(read_data, expected_data, TEST_DATA_SIZE)))
  {
    ret->val = TEST_PASSED;
  }
  else
  {
    ret->val = TEST_FAILED;
  }
  return;
}

/**
  * @brief  Import crypto persistent key
  * @param  struct test_result_t
  * @retval None
  */
static void tfm_crypto_persistent_key_import(struct test_result_t *ret)
{
  psa_status_t status;
  psa_algorithm_t alg = PSA_ALG_CBC_NO_PADDING;
  psa_key_usage_t usage = PSA_KEY_USAGE_ENCRYPT;
  psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;
  const uint8_t data[] = "THIS IS MY KEY1";

  /* Setup the key attributes with a key ID to create a persistent key */
  psa_set_key_id(&key_attributes, KEY_ID);
  psa_set_key_usage_flags(&key_attributes, usage);
  psa_set_key_algorithm(&key_attributes, alg);
  psa_set_key_type(&key_attributes, PSA_KEY_TYPE_AES);

  /* Import key data to create the persistent key */
  status = psa_import_key(&key_attributes, data, sizeof(data), &key_handle);
  if (status != PSA_SUCCESS)
  {
    ret->val = TEST_FAILED;
    return;
  }

  /* Close the persistent key handle */
  status = psa_close_key(key_handle);
  ret->val = status == PSA_SUCCESS ? TEST_PASSED : TEST_FAILED;
  return;
}

static void tfm_crypto_persistent_key_generate_simm(struct test_result_t *ret)
{
  psa_status_t status;
  psa_algorithm_t alg = PSA_ALG_CBC_NO_PADDING;
  psa_key_usage_t usage = PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT | PSA_KEY_USAGE_EXPORT;
  psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;

  /* Setup the key attributes with a key ID to create a persistent key */
  psa_set_key_id(&key_attributes, KEY_ID);
  psa_set_key_usage_flags(&key_attributes, usage);
  psa_set_key_algorithm(&key_attributes, alg);
  psa_set_key_type(&key_attributes, PSA_KEY_TYPE_AES);
  psa_set_key_bits(&key_attributes, 256);
  psa_set_key_lifetime(&key_attributes, 1);

  /* generate the persistent key */
  status = psa_generate_key(&key_attributes, &key_handle);
  if (status != PSA_SUCCESS)
  {
	printf("%i ",status);
    ret->val = TEST_FAILED;
    return;
  }

  printf("\r\n key handle %i", key_handle);

  /* Close the persistent key handle */
  status = psa_close_key(key_handle);
  ret->val = status == PSA_SUCCESS ? TEST_PASSED : TEST_FAILED;
  return;
}

static void tfm_crypto_persistent_encrypt_simm(struct test_result_t *ret)
{
	psa_cipher_operation_t handle_enc =  PSA_CIPHER_OPERATION_INIT;
	psa_cipher_operation_t handle_dec =  PSA_CIPHER_OPERATION_INIT;
	const uint8_t data[32]= "123456789012345 123456789012345";
    const uint8_t iv[] = "012345678901234";
    const size_t iv_length = PSA_BLOCK_CIPHER_BLOCK_SIZE(PSA_KEY_TYPE_AES);
    psa_status_t status;
    uint8_t decrypted_data[ENC_DEC_BUFFER_SIZE] = {0};
    size_t output_length = 0, total_output_length = 0;
    uint8_t encrypted_data[ENC_DEC_BUFFER_SIZE] = {0};
    uint32_t i;


    printf("Simmetric encryption: \r\n");
    printf("%s ",data);
    printf("   len: %i\r\n", strlen(data));

    status = psa_open_key(KEY_ID, &key_handle);
    	if (status != PSA_SUCCESS) {
    	printf("No handler found %i ",status);
    	  ret->val = TEST_FAILED;
    	  return;
    	}

   /* Setup the encryption object */
   status = psa_cipher_encrypt_setup(&handle_enc, KEY_ID, PSA_ALG_CBC_NO_PADDING);
   if (status != PSA_SUCCESS) {
	   if (status == PSA_ERROR_NOT_SUPPORTED) {
		   printf("\r\nAlgorithm NOT SUPPORTED by the implementation\r\r");
	   } else {
		   printf("\r\nError setting up cipher operation object\r\n");
	   }
	   printf("encryption setup error %i ",status);
	  		 ret->val = TEST_FAILED;
	  		 return;
   }
   /* generate the IV */
   /*status = psa_cipher_generate_iv(&handle_enc, iv, PSA_BLOCK_CIPHER_BLOCK_SIZE(PSA_KEY_TYPE_AES), &iv_length);
   if (status != PSA_SUCCESS) {
       	printf("error generating iv %i \r\n",status);
       	  ret->val = TEST_FAILED;
       	  return;
       	}
   Error -129 (PROGRAMMER ERROR) Sarebbe da generare l'IV, ma anche hardcoded non è un dramma
   */

   /* Set the IV for encryption*/
   status = psa_cipher_set_iv(&handle_enc, iv, iv_length);
   if (status != PSA_SUCCESS) {
          	printf("error setting iv %i \r\n",status);
          	  ret->val = TEST_FAILED;
          	  return;
          	}

   /*encrypt*/
   for (i = 0; i < ENC_DEC_BUFFER_SIZE; i += BYTE_SIZE_CHUNK) {
	   status = psa_cipher_update(&handle_enc, (data + i), BYTE_SIZE_CHUNK, (encrypted_data + total_output_length), (ENC_DEC_BUFFER_SIZE - total_output_length), &output_length);
	   if (status != PSA_SUCCESS) {
           printf("Error encrypting %i\r\n", status);
           status = psa_cipher_abort(&handle_enc);
           ret->val = TEST_FAILED;
           return;
       }
       total_output_length += output_length;

   }
   /*reset total output lenght*/
   output_length = 0;
   total_output_length = 0;


	printf("\r\n\n encrypted data: %s \r\n\n",encrypted_data);

	/* Setup the decryption object */
	   status = psa_cipher_decrypt_setup(&handle_dec, KEY_ID, PSA_ALG_CBC_NO_PADDING);
	   if (status != PSA_SUCCESS) {
		   if (status == PSA_ERROR_NOT_SUPPORTED) {
			   printf("\r\nAlgorithm NOT SUPPORTED by the implementation\r\r");
		   } else {
			   printf("\r\nError setting up cipher operation object\r\n");
		   }
		   printf("decryption setup error %i\r\n ",status);
		  		 ret->val = TEST_FAILED;
		  		 return;
	   }

	 /* Set the IV for decryption*/
	 status = psa_cipher_set_iv(&handle_dec, iv, iv_length);
	 if (status != PSA_SUCCESS) {
	       	printf("error setting iv %i \r\n",status);
       	    ret->val = TEST_FAILED;
	       	return;
	 }

	 /* Decrypt */
	     for (i = 0; i < ENC_DEC_BUFFER_SIZE; i += BYTE_SIZE_CHUNK) {
	    	 printf("\r\n i : %i \r\n", i);
	         status = psa_cipher_update(&handle_dec,(encrypted_data + i), BYTE_SIZE_CHUNK,(decrypted_data + total_output_length),(ENC_DEC_BUFFER_SIZE - total_output_length),&output_length);

	         if (status != PSA_SUCCESS) {
	             printf("Error during decryption\r\n");
	             status = psa_cipher_abort(&handle_dec);
	        	 ret->val = TEST_FAILED;
	             return;
	         }

	         total_output_length += output_length;
	     }

	 printf("\r\n\n decrypted data %s \r\n\n",decrypted_data);

	 status = psa_close_key(key_handle);
	 ret->val = status == PSA_SUCCESS ? TEST_PASSED : TEST_FAILED;
	 return;
}



static void tfm_crypto_persistent_key_generate(struct test_result_t *ret)
{
  psa_status_t status;
  psa_algorithm_t alg = PSA_ALG_RSA_PKCS1V15_CRYPT;
  psa_key_usage_t usage = PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT | PSA_KEY_USAGE_EXPORT;
  psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;

  /* Setup the key attributes with a key ID to create a persistent key */
  psa_set_key_id(&key_attributes, KEY_ID);
  psa_set_key_usage_flags(&key_attributes, usage);
  psa_set_key_algorithm(&key_attributes, alg);
  psa_set_key_type(&key_attributes, PSA_KEY_TYPE_RSA_KEY_PAIR);
  psa_set_key_bits(&key_attributes, 512);
  psa_set_key_lifetime(&key_attributes, 1);

  /* generate the persistent key */
  status = psa_generate_key(&key_attributes, &key_handle);
  if (status != PSA_SUCCESS)
  {
	printf("generate key error %i ",status);
    ret->val = TEST_FAILED;
    return;
  }

  printf("\r\n key handle %i", key_handle);

  /* Close the persistent key handle */
  status = psa_close_key(key_handle);
  ret->val = status == PSA_SUCCESS ? TEST_PASSED : TEST_FAILED;
  return;
}

static void tfm_crypto_persistent_encrypt(struct test_result_t *ret)
{
	const uint8_t data[24]= "never gonna give you up";
    psa_status_t status;
    uint8_t enc_out[100] = {0};
    size_t enc_out_len = 0;
    uint8_t dec_out[100] = {0};
    size_t dec_out_len = 0;


    printf("%s ",data);
    printf("   len: %i",strlen(data));

    status = psa_open_key(KEY_ID, &key_handle);
    	if (status != PSA_SUCCESS) {
    	printf("No handler found %i ",status);
    	  ret->val = TEST_FAILED;
    	  return;
    	}


	status = psa_asymmetric_encrypt(KEY_ID,PSA_ALG_RSA_PKCS1V15_CRYPT,data,strlen(data) + 1,NULL,0,enc_out,PSA_ASYMMETRIC_ENCRYPT_OUTPUT_SIZE(PSA_KEY_TYPE_RSA_KEY_PAIR,2048,PSA_ALG_RSA_PKCS1V15_CRYPT),&enc_out_len);
	//strlen(data) + 1, dato che devo cifrare anche il terminatore di stringa
	 if (status != PSA_SUCCESS) {
		 printf("encryption error %i ",status);
		 ret->val = TEST_FAILED;
		 return;
	 }

	printf("\r\n\n %s \r\n\n",enc_out);

	printf("Decrytp:\r\n");
	status = psa_asymmetric_decrypt(KEY_ID, PSA_ALG_RSA_PKCS1V15_CRYPT, enc_out, enc_out_len, NULL, 0, dec_out, PSA_ASYMMETRIC_DECRYPT_OUTPUT_SIZE(PSA_KEY_TYPE_RSA_KEY_PAIR,2048,PSA_ALG_RSA_PKCS1V15_CRYPT), &dec_out_len);
		 if (status != PSA_SUCCESS) {
			 printf("decryption error %i ",status);
			 ret->val = TEST_FAILED;
			 return;
		 }

	printf("\r\n\n %s \r\n\n",dec_out);


	status = psa_close_key(key_handle);
	 ret->val = status == PSA_SUCCESS ? TEST_PASSED : TEST_FAILED;
	 return;
}


static void tfm_crypto_persistent_key_print(struct test_result_t *ret){
    psa_status_t status;
    int comp_result;
    size_t data_len;
    uint8_t data_out[2050] = {0};

	status = psa_open_key(KEY_ID, &key_handle);
	if (status != PSA_SUCCESS) {
	printf("No handler found %i ",status);
	  ret->val = TEST_FAILED;
	  return;
	}

	status = psa_export_key(key_handle, data_out, sizeof(data_out), &data_len);
	if (status != PSA_SUCCESS) {
	  printf("Export unsuccessful %i ",status);
	  ret->val = TEST_FAILED;
	  return;
	}
	printf("key: ");
	for (size_t i = 0; i <= data_len; i++){
	 printf("%c", data_out[i]);
	}
	printf("\r\n\n");

	status = psa_close_key(key_handle);
	ret->val = status == PSA_SUCCESS ? TEST_PASSED : TEST_FAILED;
}
/**
  * @brief  Remove crypto persistent key
  * @param  struct test_result_t
  * @retval None
  */
static void tfm_crypto_persistent_key_destroy(struct test_result_t *ret)
{
  psa_status_t status;

  /* Open the previsously-created persistent key */
  status = psa_open_key(KEY_ID, &key_handle);
  if (status != PSA_SUCCESS) {
    ret->val = TEST_FAILED;
    return;
  }

  /* Destroy the persistent key */
  status = psa_destroy_key(key_handle);
  ret->val = status == PSA_SUCCESS ? TEST_PASSED : TEST_FAILED;
}

/**
  * @brief  Read persistent key and compare with expected value
  * @param  struct test_result_t
  * @retval None
  */
static void tfm_crypto_persistent_key_export(struct test_result_t *ret)
{
  psa_status_t status;
  int comp_result;
  size_t data_len;
  const uint8_t data[] = "THIS IS MY KEY1";
  uint8_t data_out[sizeof(data)] = {0};

  /* Open the previsously-created persistent key */
  status = psa_open_key(KEY_ID, &key_handle);
  if (status != PSA_SUCCESS) {
	printf("No handler found %i ",status);
    ret->val = TEST_FAILED;
    return;
  }

  /* Export the persistent key */
  status = psa_export_key(key_handle, data_out, sizeof(data_out), &data_len);
  for (size_t i = 0; i <= data_len; i++){
	  printf("%c", data_out[i]);
  }
  if (status != PSA_SUCCESS) {
    ret->val = TEST_FAILED;
    return;
  }

  if (data_len != sizeof(data)) {
    ret->val = TEST_FAILED;
    return;
  }

  /* Close the persistent key handle */
  status = psa_close_key(key_handle);
  ret->val = status == PSA_SUCCESS ? TEST_PASSED : TEST_FAILED;
  return;
}


#ifdef PSA_USE_SE_ST
#include "se_psa_id.h"

void print_data(uint8_t *data, size_t size, size_t line) {
  int32_t n_item_per_line;
  int32_t i, index = 0;

  while (index < size)
  {
    if (line != 0) {
      n_item_per_line = (size-index) >= line ? line : (size-index);
    } else {
      n_item_per_line = size;
    }
    for (i = 0; i < n_item_per_line; i++)
    {
      printf("%2.2x", data[index + i]);
    }
    printf("\r\n");
    index += n_item_per_line;

  }
  printf("\r\n");
}

void tfm_stsafe_test(struct test_result_t *ret)
{

  psa_key_handle_t key_handle;
  psa_status_t status;
  uint8_t data[1000];
  uint8_t pub_key[97];
  size_t pub_key_size = sizeof(pub_key);
  char serial_str[19];
  size_t serial_size = sizeof(serial_str);
  uint8_t hash[48];
  hash[0] = 0xFF;
  uint16_t map_size;
  int32_t i;
  psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;

  uint8_t sig[96];
  size_t sig_size = sizeof(sig);

  ret->val = TEST_FAILED;
  /* serial number key */
  status = psa_open_key(SE_ST_ID_TO_PSA_ID(SE_ST_SERIAL_NUMBER), &key_handle);
  if (status != PSA_SUCCESS)
  {
    printf("psa_open_key failed error =%d\n\r", (int)status);
    goto exit;
  }
  status = psa_export_key(key_handle, (uint8_t*)serial_str, sizeof(serial_str), &serial_size);
  if (status != PSA_SUCCESS)
  {
    printf("psa_export_key failed error =%d\n\r", (int)status);
    goto exit;
  }
  status = psa_close_key(key_handle);
  if (status != PSA_SUCCESS)
  {
    printf("psa_close_key failed error =%d\n\r", (int)status);
    goto exit;
  }
  printf("STSAFE-A Serial Number = %s\n\r", serial_str);


  /* open key slot 0 */
  status = psa_open_key(SE_ST_ID_TO_PSA_ID(SE_ST_PRIV_SLOT_0), &key_handle);
  if (status != PSA_SUCCESS)
  {
    printf("psa_open_key failed error =%d\n\r", (int)status);
    goto exit;
  }
  status = psa_export_public_key(key_handle, pub_key, sizeof(pub_key), &pub_key_size);
  if (status != PSA_SUCCESS)
  {
    printf("psa_export_public_key failed error =%d\n\r", (int)status);
    goto exit;
  }
  printf("STSAFE-A Slot 0 public key = ");
  print_data(pub_key, pub_key_size, 0);

  status = psa_asymmetric_sign(key_handle, PSA_ALG_ECDSA(PSA_ALG_SHA_256), hash, sizeof(hash), sig, sizeof(sig), &sig_size);
  if (status != PSA_SUCCESS)
  {
    printf("psa_asymmetric_sign failed error =%d\n\r", (int)status);
    goto exit;
  }

  printf("Message being signed:\n\r");
  print_data(hash, sizeof(hash), 0);

  printf("Signature with key from slot 0:\n\r");
  print_data(sig, sig_size, sig_size/2);


  status = psa_close_key(key_handle);
  if (status != PSA_SUCCESS)
  {
    printf("psa_close_key failed error =%d\n\r", (int)status);
    goto exit;
  }

  /* open key slot 1 */
  status = psa_open_key(SE_ST_ID_TO_PSA_ID(SE_ST_PRIV_SLOT_1), &key_handle);
  if (status != PSA_SUCCESS)
  {
    /* generate key on slot 1 */
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_BRAINPOOL_P_R1));
    psa_set_key_bits(&attr, 256);
    psa_set_key_lifetime(&attr, PSA_SE_ST_LIFETIME_DEFAULT);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_ANY_HASH));
    psa_set_key_id(&attr, SE_ST_ID_TO_PSA_ID(SE_ST_PRIV_SLOT_1));
    psa_set_key_usage_flags(&attr, (PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_SIGN_HASH));

    status = psa_generate_key(&attr, &key_handle);
    if (status != PSA_SUCCESS)
    {
      printf("psa_generate_key failed error =%d\n\r", (int)status);
      goto exit;
    }
  }

  status = psa_export_public_key(key_handle, pub_key, sizeof(pub_key), &pub_key_size);
  if (status != PSA_SUCCESS)
  {
    printf("psa_export_public_key failed error =%d\n\r", (int)status);
    goto exit;
  }
  printf("STSAFE-A Slot 1 public key = ");
  print_data(pub_key, pub_key_size, 0);
  
  status = psa_asymmetric_sign(key_handle, PSA_ALG_ECDSA(PSA_ALG_SHA_256), hash, sizeof(hash), sig, sizeof(sig), &sig_size);
  if (status != PSA_SUCCESS)
  {
    printf("psa_asymmetric_sign failed error =%d\n\r", (int)status);
    goto exit;
  }

  printf("Signature with key from slot 1:\n\r");
  print_data(sig, sig_size, sig_size/2);


  status = psa_close_key(key_handle);
  if (status != PSA_SUCCESS)
  {
    printf("psa_close_key failed error =%d\n\r", (int)status);
    goto exit;
  }


  /* memory 0*/
  status = psa_open_key(SE_ST_ID_TO_PSA_ID(SE_ST_MEMORY_REGION_ID(0)), &key_handle);
  if (status != PSA_SUCCESS)
  {
    printf("psa_open_key failed error =%d\n\r", (int)status);
    goto exit;
  }
  uint8_t cert_header[4];
  size_t read_size;

  status = psa_export_key(key_handle, cert_header, 4, &read_size);
  if (status != PSA_SUCCESS)
  {
    printf("psa_export_key failed error =%d\n\r", (int)status);
    goto exit;
  }

  read_size = ((cert_header[2] << 8) | cert_header[3]) + 4;
  printf("Certificate size = %d\n\r", read_size);
  status = psa_export_key(key_handle, data, read_size, &read_size);
  if (status != PSA_SUCCESS)
  {
    printf("psa_export_key failed error =%d\n\r", (int)status);
    goto exit;
  }
  status = psa_close_key(key_handle);
  if (status != PSA_SUCCESS)
  {
    printf("psa_close_key failed error =%d\n\r", (int)status);
    goto exit;
  }

  print_data(data, read_size, 16);

  /* get mapping size */
  status = psa_open_key(SE_ST_ID_TO_PSA_ID(SE_ST_MAPPING), &key_handle);
  if (status != PSA_SUCCESS)
  {
    printf("psa_open_key failed error =%d\n\r", (int)status);
    goto exit;
  }

  status = psa_export_key(key_handle, data, sizeof(data), &read_size);
  map_size = *(uint16_t*)data;
  printf("Mapping size = %d (%d)\n\r", map_size, read_size);
  if (status != PSA_SUCCESS)
  {
    printf("psa_export_key failed error =%d\n\r", (int)status);
    goto exit;
  }
  status = psa_close_key(key_handle);
  if (status != PSA_SUCCESS)
  {
    printf("psa_close_key failed error =%d\n\r", (int)status);
    goto exit;
  }


  for (i = 0; i < map_size; i++)
  {
    /* get memory region */
    status = psa_open_key(SE_ST_ID_TO_PSA_ID(SE_ST_MEMORY_REGION_ID(i)), &key_handle);
    if (status != PSA_SUCCESS)
    {
      printf("psa_open_key failed error =%d\n\r", (int)status);
      goto exit;
    }

    status = psa_export_key(key_handle, data, 200, &read_size);
    if (status != PSA_SUCCESS)
    {
      printf("psa_export_key failed error =%d\n\r", (int)status);
      goto exit;
    }
    printf("region %d data : \n\r", (int)i);
    print_data(data, read_size, 16);

    status = psa_close_key(key_handle);
    if (status != PSA_SUCCESS)
    {
      printf("psa_close_key failed error =%d\n\r", (int)status);
      goto exit;
    }
  }

  /* Test import in memory region 1 */
  psa_set_key_id(&attr, SE_ST_ID_TO_PSA_ID(SE_ST_MEMORY_REGION_ID(1)));
  psa_set_key_lifetime(&attr, PSA_SE_ST_LIFETIME_DEFAULT);
  psa_set_key_bits(&attr, sig_size * 8);
  psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_EXPORT);
  psa_set_key_type(&attr, PSA_KEY_TYPE_RAW_DATA);

  /* Fill the region with the signature generated previously */
  status = psa_import_key(&attr, sig, sig_size, &key_handle);
  if (status != PSA_SUCCESS) {
    printf("psa_import_key failed error =%d\n\r", (int)status);
    goto exit;
  }
  status = psa_export_key(key_handle, data, sig_size, &read_size);
  if (status != PSA_SUCCESS) {
    printf("psa_export_key failed error =%d\n\r", (int)status);
    goto exit;
  }
  printf("region %d data : \n\r", 1);
  print_data(data, read_size, 16);

  if ( memcmp(data, sig, sig_size) )
  {
    printf("data content mismatched from region 1\n\r");
    goto exit;
  }

  status = psa_close_key(key_handle);
  if (status != PSA_SUCCESS) {
    printf("psa_close_key failed error =%d\n\r", (int)status);
    goto exit;
  }


  ret->val = TEST_PASSED;
exit:
  return;
}
#endif /* PSA_USE_SE_ST */

void dump_eat_token(struct q_useful_buf_c *token)
{
  int32_t len = token->len;
  int32_t n_item_per_line;
  int32_t i, index = 0;
  uint8_t *byte = (uint8_t *)token->ptr;
  while (index < len)
  {
    n_item_per_line = (len-index) >= 20 ? 20 : (len-index);
    for (i = 0; i < n_item_per_line; i++)
    {
      printf("%2.2x", byte[index + i]);
    }
    printf("\r\n");
    index += n_item_per_line;

  }
  printf("\r\n");

}

/**
  * @brief  request eat short cicuit, check result and
  * display response result buffer.
  * @param  struct test_result_t
  * @retval None
  */
static void tfm_eat_test_circuit_sig(uint32_t encode_options, struct test_result_t *ret)
{
  psa_status_t status;
  Q_USEFUL_BUF_MAKE_STACK_UB(token_storage, PSA_INITIAL_ATTEST_TOKEN_MAX_SIZE);
  struct q_useful_buf_c completed_token;
  struct q_useful_buf_c tmp;

  /* -- Make a token with all the claims -- */
  tmp = TOKEN_TEST_VALUE_NONCE;
  printf("token request value :\r\n");
  dump_eat_token(&tmp);
  status = token_main_alt(encode_options,
                          tmp,
                          token_storage,
                          &completed_token);
  if (status == PSA_SUCCESS)
  {
    ret->val = TEST_PASSED;
    printf("token response value :\r\n");
    dump_eat_token(&completed_token);
  }
  else
  {
    printf("failed status %d\r\n", (int)status);
    ret->val = TEST_FAILED;
  }

}
/**
  * \brief An alternate token_main() that packs the option flags into the nonce.
  *
  * \param[in] option_flags      Flag bits to pack into nonce.
  * \param[in] nonce             Pointer and length of the nonce.
  * \param[in] buffer            Pointer and length of buffer to
  *                              output the token into.
  * \param[out] completed_token  Place to put pointer and length
  *                              of completed token.
  *
  * \return various errors. See \ref attest_token_err_t.
  *
  */
static psa_status_t token_main_alt(uint32_t option_flags,
                                            struct q_useful_buf_c nonce,
                                            struct q_useful_buf buffer,
                                            struct q_useful_buf_c *completed_token)
{
  psa_status_t return_value;
  size_t completed_token_len;
  struct q_useful_buf_c        actual_nonce;
  Q_USEFUL_BUF_MAKE_STACK_UB(actual_nonce_storage, 64);

  if (nonce.len == 64 && q_useful_buf_is_value(nonce, 0))
  {
    /* Go into special option-packed nonce mode */
    actual_nonce = q_useful_buf_copy(actual_nonce_storage, nonce);
    /* Use memcpy as it always works and avoids type punning */
    memcpy((uint8_t *)actual_nonce_storage.ptr,
           &option_flags,
           sizeof(uint32_t));
  }
  else
  {
    actual_nonce = nonce;
  }

  completed_token_len = buffer.len;
  return_value = psa_initial_attest_get_token(actual_nonce.ptr,
                                              (uint32_t)actual_nonce.len,
                                              buffer.ptr,
                                              buffer.len,
                                              &completed_token_len);

  *completed_token = (struct q_useful_buf_c)
  {
    buffer.ptr, completed_token_len
  };

  return return_value;
}

/**
  * @}
  */
