/*
 * Copyright (c) 2019-2021, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

/*********** WARNING: This is an auto-generated file. Do not edit! ***********/

#ifdef TFM_PARTITION_PROTECTED_STORAGE
#include "psa_manifest/tfm_protected_storage.h"
#endif /* TFM_PARTITION_PROTECTED_STORAGE */

#ifdef TFM_PARTITION_INTERNAL_TRUSTED_STORAGE
#include "psa_manifest/tfm_internal_trusted_storage.h"
#endif /* TFM_PARTITION_INTERNAL_TRUSTED_STORAGE */

#ifdef TFM_PARTITION_CRYPTO
#include "psa_manifest/tfm_crypto.h"
#endif /* TFM_PARTITION_CRYPTO */

#ifdef TFM_PARTITION_PLATFORM
#include "psa_manifest/tfm_platform.h"
#endif /* TFM_PARTITION_PLATFORM */

#ifdef TFM_PARTITION_INITIAL_ATTESTATION
#include "psa_manifest/tfm_initial_attestation.h"
#endif /* TFM_PARTITION_INITIAL_ATTESTATION */

#ifdef TFM_PARTITION_TEST_CORE
#include "psa_manifest/tfm_ss_core_test.h"
#endif /* TFM_PARTITION_TEST_CORE */

#ifdef TFM_PARTITION_TEST_CORE
#include "psa_manifest/tfm_ss_core_test_2.h"
#endif /* TFM_PARTITION_TEST_CORE */

#ifdef TFM_PARTITION_TEST_SECURE_SERVICES
#include "psa_manifest/tfm_secure_client_service.h"
#endif /* TFM_PARTITION_TEST_SECURE_SERVICES */

#ifdef TFM_PARTITION_TEST_CORE_IPC
#include "psa_manifest/tfm_ipc_service_test.h"
#endif /* TFM_PARTITION_TEST_CORE_IPC */

#ifdef TFM_PARTITION_TEST_CORE_IPC
#include "psa_manifest/tfm_ipc_client_test.h"
#endif /* TFM_PARTITION_TEST_CORE_IPC */

#ifdef TFM_ENABLE_IRQ_TEST
#include "psa_manifest/tfm_irq_test_service_1.h"
#endif /* TFM_ENABLE_IRQ_TEST */

#ifdef TFM_PARTITION_TEST_PS
#include "psa_manifest/tfm_ps_test_service.h"
#endif /* TFM_PARTITION_TEST_PS */

#ifdef TFM_PARTITION_TEST_SECURE_SERVICES
#include "psa_manifest/tfm_secure_client_2.h"
#endif /* TFM_PARTITION_TEST_SECURE_SERVICES */

#ifdef TFM_PARTITION_FIRMWARE_UPDATE
#include "psa_manifest/tfm_firmware_update.h"
#endif /* TFM_PARTITION_FIRMWARE_UPDATE */

#ifdef TFM_PARTITION_APP_ROT
#include "psa_manifest/tfm_app_rot.h"
#endif /* TFM_PARTITION_APP_ROT */

#ifdef TFM_PARTITION_FFM11
#include "psa_manifest/tfm_ffm11_partition.h"
#endif /* TFM_PARTITION_FFM11 */


#include "cmsis_compiler.h"

/* Definitions of the signals of the IRQs (if any) */
const struct tfm_core_irq_signal_data_t tfm_core_irq_signals[] = {
#ifdef TFM_PARTITION_PLATFORM
    { TFM_SP_PLATFORM, SPM_TAMPER_IRQ, TAMP_IRQ, 64 },
    { TFM_SP_PLATFORM, SPM_GTZC_IRQ, GTZC_IRQ, 64 },
#endif /* TFM_PARTITION_PLATFORM */
#ifdef TFM_ENABLE_IRQ_TEST
    { TFM_IRQ_TEST_1, SPM_CORE_IRQ_TEST_1_SIGNAL_TIMER_0_IRQ, TFM_TIMER0_IRQ, 64 },
#endif /* TFM_ENABLE_IRQ_TEST */
   {0, 0, (IRQn_Type)0, 0}              /* add dummy element to avoid non-standard empty array */
};

const size_t tfm_core_irq_signals_count = (sizeof(tfm_core_irq_signals) /
                                           sizeof(*tfm_core_irq_signals)) - 1; /* adjust for the dummy element */

/* Definitions of privileged IRQ handlers (if any) */
#ifdef TFM_PARTITION_PLATFORM
void TAMP_IRQHandler(void)
{
    tfm_set_irq_signal(TFM_SP_PLATFORM, SPM_TAMPER_IRQ, TAMP_IRQ);
}

void GTZC_IRQHandler(void)
{
    tfm_set_irq_signal(TFM_SP_PLATFORM, SPM_GTZC_IRQ, GTZC_IRQ);
}

#endif /* TFM_PARTITION_PLATFORM */

#ifdef TFM_ENABLE_IRQ_TEST
void TFM_TIMER0_IRQHandler(void)
{
    tfm_set_irq_signal(TFM_IRQ_TEST_1, SPM_CORE_IRQ_TEST_1_SIGNAL_TIMER_0_IRQ, TFM_TIMER0_IRQ);
}

#endif /* TFM_ENABLE_IRQ_TEST */

