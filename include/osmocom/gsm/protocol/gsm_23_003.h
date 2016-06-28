#pragma once

/* Chapter 2.2 */
#define GSM23003_IMSI_MAX_DIGITS	15
/* Chapter 2.4 */
#define GSM23003_TMSI_NUM_BYTES		4
/* Chapter 2.5 */
#define GSM23003_LMSI_NUM_BYTES		4
/* Chapter 2.6 */
#define GSM23003_TLLI_NUM_BYTES		4
/* Chapter 2.7 */
#define GSM23003_PTMSI_SIG_NUM_BYTES	3
/* Chapter 2.8 */
#define GSM23003_MME_CODE_NUM_BYTES	1
#define GSM23003_MME_GROUP_NUM_BYTES	2
#define GSM23003_MTMSI_NUM_BYTES	4
/* Chapter 6.2.1 */
#define GSM23003_IMEI_TAC_NUM_DIGITS	8
#define GSM23003_IMEI_SNR_NUM_DIGITS	6
#define GSM23003_IMEI_NUM_DIGITS	(GSM23003_IMEI_TAC_NUM_DIGITS + \
					 GSM23003_IMEI_SNR_NUM_DIGITS + 1)
#define GSM23003_IMEISV_NUM_DIGITS	(GSM23003_IMEI_TAC_NUM_DIGITS + \
					 GSM23003_IMEI_SNR_NUM_DIGITS + 2)