/*
 * Copyright 2014 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include "s2n_test.h"

#include "stuffer/s2n_stuffer.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_config.h"
#include "crypto/s2n_rsa.h"
#include "crypto/s2n_dhe.h"
#include "crypto/s2n_fips.h"

static uint8_t certificate[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDLjCCAhYCCQDL1lr6N8/gvzANBgkqhkiG9w0BAQUFADBZMQswCQYDVQQGEwJB\n"
    "VTETMBEGA1UECBMKU29tZS1TdGF0ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0\n"
    "cyBQdHkgTHRkMRIwEAYDVQQDEwlsb2NhbGhvc3QwHhcNMTQwNTEwMTcwODIzWhcN\n"
    "MjQwNTA3MTcwODIzWjBZMQswCQYDVQQGEwJBVTETMBEGA1UECBMKU29tZS1TdGF0\n"
    "ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMRIwEAYDVQQDEwls\n"
    "b2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDIltaUmHg+\n"
    "G7Ida2XCtEQx1YeWDX41U2zBKbY0lT+auXf81cT3dYTdfJblb+v4CTWaGNofogcz\n"
    "ebm8B2/OF9F+WWkKAJhKsTPAE7/SNAdi4Eqv4FfNbWKkGb4xacxxb4PH2XP9V3Ch\n"
    "J6lMSI3V68FmEf4kcEN14V8vufIC5HE/LT4gCPDJ4UfUUbAgEhSebT6r/KFYB5T3\n"
    "AeDc1VdnaaRblrP6KwM45vTs0Ii09/YrlzBxaTPMjLGCKa8JMv8PW2R0U9WCqHmz\n"
    "BH+W3Q9xPrfhCInm4JWob8WgM1NuiYuzFB0CNaQcdMS7h0aZEAVnayhQ96/Padpj\n"
    "KNE0Lur9nUxbAgMBAAEwDQYJKoZIhvcNAQEFBQADggEBAGRV71uRt/1dADsMD9fg\n"
    "JvzW89jFAN87hXCRhTWxfXhYMzknxJ5WMb2JAlaMc/gTpiDiQBkbvB+iJe5AepgQ\n"
    "WbyxPJNtSlA9GfKBz1INR5cFsOL27VrBoMYHMaolveeslc1AW2HfBtXWXeWSEF7F\n"
    "QNgye8ZDPNzeSWSI0VyK2762wsTgTuUhHAaJ45660eX57+e8IvaM7xOEfBPDKYtU\n"
    "0a28ZuhvSr2akJtGCwcs2J6rs6I+rV84UktDxFC9LUezBo8D9FkMPLoPKKNH1dXR\n"
    "6LO8GOkqWUrhPIEmfy9KYes3q2ZX6svk4rwBtommHRv30kPxnnU1YXt52Ri+XczO\n" "wEs=\n" "-----END CERTIFICATE-----\n";

static uint8_t chain[] = 
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDLjCCAhYCCQDL1lr6N8/gvzANBgkqhkiG9w0BAQUFADBZMQswCQYDVQQGEwJB\n"
    "VTETMBEGA1UECBMKU29tZS1TdGF0ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0\n"
    "cyBQdHkgTHRkMRIwEAYDVQQDEwlsb2NhbGhvc3QwHhcNMTQwNTEwMTcwODIzWhcN\n"
    "MjQwNTA3MTcwODIzWjBZMQswCQYDVQQGEwJBVTETMBEGA1UECBMKU29tZS1TdGF0\n"
    "ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMRIwEAYDVQQDEwls\n"
    "b2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDIltaUmHg+\n"
    "G7Ida2XCtEQx1YeWDX41U2zBKbY0lT+auXf81cT3dYTdfJblb+v4CTWaGNofogcz\n"
    "ebm8B2/OF9F+WWkKAJhKsTPAE7/SNAdi4Eqv4FfNbWKkGb4xacxxb4PH2XP9V3Ch\n"
    "J6lMSI3V68FmEf4kcEN14V8vufIC5HE/LT4gCPDJ4UfUUbAgEhSebT6r/KFYB5T3\n"
    "AeDc1VdnaaRblrP6KwM45vTs0Ii09/YrlzBxaTPMjLGCKa8JMv8PW2R0U9WCqHmz\n"
    "BH+W3Q9xPrfhCInm4JWob8WgM1NuiYuzFB0CNaQcdMS7h0aZEAVnayhQ96/Padpj\n"
    "KNE0Lur9nUxbAgMBAAEwDQYJKoZIhvcNAQEFBQADggEBAGRV71uRt/1dADsMD9fg\n"
    "JvzW89jFAN87hXCRhTWxfXhYMzknxJ5WMb2JAlaMc/gTpiDiQBkbvB+iJe5AepgQ\n"
    "WbyxPJNtSlA9GfKBz1INR5cFsOL27VrBoMYHMaolveeslc1AW2HfBtXWXeWSEF7F\n"
    "QNgye8ZDPNzeSWSI0VyK2762wsTgTuUhHAaJ45660eX57+e8IvaM7xOEfBPDKYtU\n"
    "0a28ZuhvSr2akJtGCwcs2J6rs6I+rV84UktDxFC9LUezBo8D9FkMPLoPKKNH1dXR\n"
    "6LO8GOkqWUrhPIEmfy9KYes3q2ZX6svk4rwBtommHRv30kPxnnU1YXt52Ri+XczO\n" "wEs=\n" "-----END CERTIFICATE-----\n"
"-----BEGIN CERTIFICATE-----\n"
"MIIEozCCA4ugAwIBAgIQWrYdrB5NogYUx1U9Pamy3DANBgkqhkiG9w0BAQUFADCB\n"
"lzELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAlVUMRcwFQYDVQQHEw5TYWx0IExha2Ug\n"
"Q2l0eTEeMBwGA1UEChMVVGhlIFVTRVJUUlVTVCBOZXR3b3JrMSEwHwYDVQQLExho\n"
"dHRwOi8vd3d3LnVzZXJ0cnVzdC5jb20xHzAdBgNVBAMTFlVUTi1VU0VSRmlyc3Qt\n"
"SGFyZHdhcmUwHhcNMDgxMDIzMDAwMDAwWhcNMjAwNTMwMTA0ODM4WjBBMQswCQYD\n"
"VQQGEwJGUjESMBAGA1UEChMJR0FOREkgU0FTMR4wHAYDVQQDExVHYW5kaSBTdGFu\n"
"ZGFyZCBTU0wgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC2VD2l\n"
"2w0ieFBqWiOJP5eh1AcaqVgIm6AVwzK2t/HouaVvrTf2bnEbtHUtSF6fxhWqge/l\n"
"xIiVijpsd8y1zWXkZ+VzyVBSlMEnST6ga0EWQbaUmUGuPsviBkYJ6U2+yUxVqRh+\n"
"pt9u/UqyzGxO2chQFZOz8unjwmqtOtX7w3lQnyV5KbJHZHwgPuIITZMpFLY0bs9x\n"
"Rn52EPT9bKoB0sIG3pKDzFiQLpLeHmW3Yy89sutwjEzgvhWd3sFNVvgLxo4HuV3f\n"
"lfB7QB8aLNecK0t29Fn1Q8EsZhCenmaWYJ0cdBtOGFwIsG5symkaAum7ynjvZi7j\n"
"Mv1BXJV0gU302v5LAgMBAAGjggE+MIIBOjAfBgNVHSMEGDAWgBShcl8mGyiYQ5Vd\n"
"BzfVhZadS9LDRTAdBgNVHQ4EFgQUtqj/oqgv0KbNS7Fo8+dQEDGneSEwDgYDVR0P\n"
"AQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAwGAYDVR0gBBEwDzANBgsrBgEE\n"
"AbIxAQICGjBEBgNVHR8EPTA7MDmgN6A1hjNodHRwOi8vY3JsLnVzZXJ0cnVzdC5j\n"
"b20vVVROLVVTRVJGaXJzdC1IYXJkd2FyZS5jcmwwdAYIKwYBBQUHAQEEaDBmMD0G\n"
"CCsGAQUFBzAChjFodHRwOi8vY3J0LnVzZXJ0cnVzdC5jb20vVVROQWRkVHJ1c3RT\n"
"ZXJ2ZXJfQ0EuY3J0MCUGCCsGAQUFBzABhhlodHRwOi8vb2NzcC51c2VydHJ1c3Qu\n"
"Y29tMA0GCSqGSIb3DQEBBQUAA4IBAQAZU78DPZvia1r9ukkfT+zhxoI5PNIDBA+r\n"
"ez6CqYUQH/TeMq9YP/9w8zAdly1MmuLsDD4ULS+YSJ2uFmqsLUKqtWSkcLvrc5R7\n"
"RkznehR2W0wdhKEgdB8uS1xwiNy99xk97VkN4j8m4pyspDyVHPi+jAOu8OWcTbzH\n"
"m1gAv6+t+jducW0YNA7B6mr4Dd9pVFYV8iiz/qRj7MUEZGC7/irw9IehsK69quQv\n"
"4wMLL2ZfhaQye0btJQzn8bfnGf1gul+Hd96YB5bkXupjfajeVdphXDyQg0MEBzzd\n"
"8/ifBlIK3se2e4/hEfcEejX/arxbx1BJCHBvlEPNnsdw8dvQbdqP\n"
"-----END CERTIFICATE-----\n";

static uint8_t private_key[] =
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEpAIBAAKCAQEAyJbWlJh4PhuyHWtlwrREMdWHlg1+NVNswSm2NJU/mrl3/NXE\n"
    "93WE3XyW5W/r+Ak1mhjaH6IHM3m5vAdvzhfRfllpCgCYSrEzwBO/0jQHYuBKr+BX\n"
    "zW1ipBm+MWnMcW+Dx9lz/VdwoSepTEiN1evBZhH+JHBDdeFfL7nyAuRxPy0+IAjw\n"
    "yeFH1FGwIBIUnm0+q/yhWAeU9wHg3NVXZ2mkW5az+isDOOb07NCItPf2K5cwcWkz\n"
    "zIyxgimvCTL/D1tkdFPVgqh5swR/lt0PcT634QiJ5uCVqG/FoDNTbomLsxQdAjWk\n"
    "HHTEu4dGmRAFZ2soUPevz2naYyjRNC7q/Z1MWwIDAQABAoIBAHrkryLrJwAmR8Hu\n"
    "grH/b6h4glFUgvZ43jCaNZ+RsR5Cc1jcP4i832Izat+26oNUYRrADyNCSdcnxLuG\n"
    "cuF5hkg6zzfplWRtnJ8ZenR2m+/gKuIGOMULN1wCyZvMjg0RnVNbzsxwPfj+K6Mo\n"
    "8H0Xq621aFc60JnwMjkzWyqaeyeQogn1pqybuL6Dm2huvN49LR64uHuDUStTRX33\n"
    "ou1fVWXOJ1kealYPbRPj8pDa31omB8q5Cf8Qe/b9anqyi9CsP17QbVg9k2IgoLlj\n"
    "agqOc0u/opOTZB4tqJbqsIdEhc5LD5RUkYJsw00Iq0RSiKTfiWSPyOFw99Y9Act0\n"
    "cbIIxEECgYEA8/SOsQjoUX1ipRvPbfO3suV1tU1hLCQbIpv7WpjNr1kHtngjzQMP\n"
    "dU/iriUPGF1H+AxJJcJQfCVThV1AwFYVKb/LCrjaxlneZSbwfehpjo+xQGaNYG7Q\n"
    "1vQuBVejuYk/IvpZltQOdm838DjvYyWDMh4dcMFIycXxEg+oHxf/s+8CgYEA0n4p\n"
    "GBuLUNx9vv3e84BcarLaOF7wY7tb8z2oC/mXztMZpKjovTH0PvePgI5/b3KQ52R0\n"
    "8zXHVX/4lSQVtCuhOVwKOCQq97/Zhlp5oTTShdQ0Qa1GQRl5wbTS6hrYEWSi9AQP\n"
    "BVUPZ+RIcxx00DfBNURkId8xEpvCOmvySN8sUlUCgYAtXmHbEqkB3qulwRJGhHi5\n"
    "UGsfmJBlwSE6wn9wTdKStZ/1k0o1KkiJrJ2ffUzdXxuvSbmgyA5nyBlMSBdurZOp\n"
    "+/0qtU4abUQq058OC1b2KEryix/nuzQjha25WJ8eNiQDwUNABZfa9rwUdMIwUh2g\n"
    "CHG5Mnjy7Vjz3u2JOtFXCQKBgQCVRo1EIHyLauLuaMINM9HWhWJGqeWXBM8v0GD1\n"
    "pRsovQKpiHQNgHizkwM861GqqrfisZZSyKfFlcynkACoVmyu7fv9VoD2VCMiqdUq\n"
    "IvjNmfE5RnXVQwja+668AS+MHi+GF77DTFBxoC5VHDAnXfLyIL9WWh9GEBoNLnKT\n"
    "hVm8RQKBgQCB9Skzdftc+14a4Vj3NCgdHZHz9mcdPhzJXUiQyZ3tYhaytX9E8mWq\n"
    "pm/OFqahbxw6EQd86mgANBMKayD6B1Id1INqtXN1XYI50bSs1D2nOGsBM7MK9aWD\n" "JXlJ2hwsIc4q9En/LR3GtBaL84xTHGfznNylNhXi7GbO1wNMJuAukA==\n" "-----END RSA PRIVATE KEY-----\n";

static uint8_t unmatched_private_key[] =
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEpQIBAAKCAQEA6ddvtO6DbX5GLrWeXD2jufmR6lvYuzwpIHbDf0RQr2AT50wf\n"
    "vV+sMYVa/d4g68tqtihH691tqzKevVc25LXM0a0f0NfnrNibyA1/66CwFQsyy1j2\n"
    "U90BdguI/ZxqEV58ee/PzerOoS5d/rgBALzGwwYwyvlzr35KGjfRZ4XOFoToKnkN\n"
    "0mR44firCvb7dJ53QRXoPbkYpQQQ3vMWMOtDZoPsvP0dJJ50B7LaFL6nbOyJmZ2T\n"
    "evaAov1Nuk5QSrZf2icpuQVXxuu2xLmTNL25OUiV3t7ZjiLtrOZrmrIzv8/sLcWp\n"
    "VJcFWFoKizmjvpDfD086a9c81vo4kqgD/RZ9dQIDAQABAoIBAQDBNUzJ3MxgupW4\n"
    "YD2BDzjpH2jNj6fKRBHjDd3HmKVl0eeAE2iiKpt2qy2cVl0zFfaMnUmXe3PyoLeB\n"
    "z76+R+v8TqPcBZgZOzuzllvcTv9N09vbIh0c+50KcMt2aDdHNJ96jIdRJzIlAM+O\n"
    "9290sYU0fDfybRuFo74MXZQ6idbWyNMjXEv2oPrmvMmOHm10sz9BCXWFUpDpDFKD\n"
    "8xgw1GZ1QeHITWoQXMI2uJUFFj2hYbRAl6f8cMXVjUipmMNpfJk4CbtEdSMPkjrz\n"
    "XgIVrMCorCiaLuVQgSQCHB01n8ETM6R9PYSgMSg3RYYqKq4N0nvREUf4VvKV8JOY\n"
    "EGzNgq3BAoGBAPvHPoCKQawLEr4jE5ITMqhZXlBXh8aU7LetjSY1BfnsiH43eg1n\n"
    "186lfOX0r1I2KkVZTehZohkEo8xeEpc+XMdux1z0mX2uz1tfmHl838sRaTBs1JZ0\n"
    "slkBrASfDdOnLlHCMhRmFEEnA0eelNYCiy/Ak0UX7NpuhZ3bh2jGemixAoGBAO3D\n"
    "MupFbCl64AFEuLCA3wSFRhG82AScYAF1txoTM01V/kqy66j2jJsqMXkVcyBcLBkJ\n"
    "5ozW4kIKkh0dYtIjDpsnXKBK/kVcvJN+60hwVnAMFFJPlRCdejkKSsSe9xod+FzU\n"
    "DvwWLpLaO3sFtykGHelFbzMDB6FaZQFSfSMsNhIFAoGBAKaNafor+z9s38wpdfPG\n"
    "gVc+LxakoGur7l+fDeU9ZCOs5ang1vtxOyA29sVDtIqEzDet2MygJou4NwalIFUu\n"
    "ar9+t6D1KWgrsH24YivTgFNbxCLFi2ev8J7SbVFtSf8983UgKnK2CCYFQbUp4Tkk\n"
    "26AOGx20svjX7cm8A/o6eZUxAoGBANtedXSnNuOSpmklMc5QKPRvzrWA6kJe0Umn\n"
    "hZf+TSA2jlf3eu07BYIITPst6jnaMSms89XQUZOjUyqfuVSu2cQXbiPK7Y2rwaXI\n"
    "vWbplybsTjefi6Z31ZQZReDh1pV3P3bOhUDban898RFRtauZJDHdSXrkeb7Ku1Sb\n"
    "+i9glEbNAoGAJngXJZ2djyzCxYtSNyUFP8AZfmSy+vmHVCCri1FCoFfj9D1HTw4h\n"
    "G0guyN3/Qm51gJVeBTOu/dtoA5JAZi6CRyNuhClLCqV+jGsUr9xyMzA+t/JHVr+0\n"
    "XQhx4wqVYQs2852qaJg+wYUi50FtRT6hLyDQmg9ttvS4YIwMTdVzl2Q=\n"
    "-----END RSA PRIVATE KEY-----\n";

static uint8_t dhparams[] =
    "-----BEGIN DH PARAMETERS-----\n"
    "MIIBCAKCAQEAy1+hVWCfNQoPB+NA733IVOONl8fCumiz9zdRRu1hzVa2yvGseUSq\n"
    "Bbn6k0FQ7yMED6w5XWQKDC0z2m0FI/BPE3AjUfuPzEYGqTDf9zQZ2Lz4oAN90Sud\n"
    "luOoEhYR99cEbCn0T4eBvEf9IUtczXUZ/wj7gzGbGG07dLfT+CmCRJxCjhrosenJ\n"
    "gzucyS7jt1bobgU66JKkgMNm7hJY4/nhR5LWTCzZyzYQh2HM2Vk4K5ZqILpj/n0S\n"
    "5JYTQ2PVhxP+Uu8+hICs/8VvM72DznjPZzufADipjC7CsQ4S6x/ecZluFtbb+ZTv\n" "HI5CnYmkAwJ6+FSWGaZQDi8bgerFk9RWwwIBAg==\n" "-----END DH PARAMETERS-----\n";

int main(int argc, char **argv)
{
    struct s2n_stuffer certificate_in, certificate_out;
    struct s2n_stuffer dhparams_in, dhparams_out;
    struct s2n_stuffer rsa_key_in, rsa_key_out;
    struct s2n_blob b;

    BEGIN_TEST();

    EXPECT_SUCCESS(s2n_stuffer_alloc(&certificate_in, sizeof(certificate)));
    EXPECT_SUCCESS(s2n_stuffer_alloc(&certificate_out, sizeof(certificate)));
    EXPECT_SUCCESS(s2n_stuffer_alloc(&dhparams_in, sizeof(dhparams)));
    EXPECT_SUCCESS(s2n_stuffer_alloc(&dhparams_out, sizeof(dhparams)));
    EXPECT_SUCCESS(s2n_stuffer_alloc(&rsa_key_in, sizeof(private_key)));
    EXPECT_SUCCESS(s2n_stuffer_alloc(&rsa_key_out, sizeof(private_key)));

    b.data = certificate;
    b.size = sizeof(certificate);
    EXPECT_SUCCESS(s2n_stuffer_write(&certificate_in, &b));

    b.data = private_key;
    b.size = sizeof(private_key);
    EXPECT_SUCCESS(s2n_stuffer_write(&rsa_key_in, &b));

    b.data = dhparams;
    b.size = sizeof(dhparams);
    EXPECT_SUCCESS(s2n_stuffer_write(&dhparams_in, &b));

    EXPECT_SUCCESS(s2n_stuffer_certificate_from_pem(&certificate_in, &certificate_out));
    EXPECT_SUCCESS(s2n_stuffer_rsa_private_key_from_pem(&rsa_key_in, &rsa_key_out));
    EXPECT_SUCCESS(s2n_stuffer_dhparams_from_pem(&dhparams_in, &dhparams_out));

    struct s2n_rsa_private_key priv_key;
    struct s2n_rsa_public_key pub_key;

    b.size = s2n_stuffer_data_available(&certificate_out);
    b.data = s2n_stuffer_raw_read(&certificate_out, b.size);
    EXPECT_SUCCESS(s2n_asn1der_to_rsa_public_key(&pub_key, &b));

    b.size = s2n_stuffer_data_available(&rsa_key_out);
    b.data = s2n_stuffer_raw_read(&rsa_key_out, b.size);
    EXPECT_SUCCESS(s2n_asn1der_to_rsa_private_key(&priv_key, &b));

    EXPECT_SUCCESS(s2n_rsa_keys_match(&pub_key, &priv_key));

    struct s2n_config *config;
    EXPECT_NOT_NULL(config = s2n_config_new());
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key(config, (char *)chain, (char *)private_key));

    struct s2n_dh_params dh_params;
    b.size = s2n_stuffer_data_available(&dhparams_out);
    b.data = s2n_stuffer_raw_read(&dhparams_out, b.size);
    EXPECT_SUCCESS(s2n_pkcs3_to_dh_params(&dh_params, &b));

    EXPECT_SUCCESS(s2n_config_add_dhparams(config, (char *)dhparams));

    /* Try signing and verification with RSA */
    uint8_t inputpad[] = "Hello world!";
    struct s2n_blob signature;
    struct s2n_hash_state tls10_one, tls10_two, tls12_one, tls12_two;

    EXPECT_SUCCESS(s2n_alloc(&signature, s2n_rsa_public_encrypted_size(&pub_key)));

    if (s2n_hash_is_available(S2N_HASH_MD5_SHA1)) {
        /* TLS 1.0 use of RSA with DHE is not permitted when FIPS mode is set */
        EXPECT_SUCCESS(s2n_hash_new(&tls10_one));
        EXPECT_SUCCESS(s2n_hash_new(&tls10_two));

        EXPECT_SUCCESS(s2n_hash_init(&tls10_one, S2N_HASH_MD5_SHA1));
        EXPECT_SUCCESS(s2n_hash_init(&tls10_two, S2N_HASH_MD5_SHA1));

        EXPECT_SUCCESS(s2n_hash_update(&tls10_one, inputpad, sizeof(inputpad)));
        EXPECT_SUCCESS(s2n_hash_update(&tls10_two, inputpad, sizeof(inputpad)));
        EXPECT_SUCCESS(s2n_rsa_sign(&priv_key, &tls10_one, &signature));
        EXPECT_SUCCESS(s2n_rsa_verify(&pub_key, &tls10_two, &signature));

        EXPECT_SUCCESS(s2n_hash_free(&tls10_one));
        EXPECT_SUCCESS(s2n_hash_free(&tls10_two));
    }

    /* TLS 1.2 use of RSA with DHE is permitted for FIPS and non-FIPS */
    EXPECT_SUCCESS(s2n_hash_new(&tls12_one));
    EXPECT_SUCCESS(s2n_hash_new(&tls12_two));

    EXPECT_SUCCESS(s2n_hash_init(&tls12_one, S2N_HASH_SHA1));
    EXPECT_SUCCESS(s2n_hash_init(&tls12_two, S2N_HASH_SHA1));

    EXPECT_SUCCESS(s2n_hash_update(&tls12_one, inputpad, sizeof(inputpad)));
    EXPECT_SUCCESS(s2n_hash_update(&tls12_two, inputpad, sizeof(inputpad)));
    EXPECT_SUCCESS(s2n_rsa_sign(&priv_key, &tls12_one, &signature));
    EXPECT_SUCCESS(s2n_rsa_verify(&pub_key, &tls12_two, &signature));

    EXPECT_SUCCESS(s2n_hash_free(&tls12_one));
    EXPECT_SUCCESS(s2n_hash_free(&tls12_two));

    EXPECT_SUCCESS(s2n_config_free(config));

    /* Mismatched public/private key should fail */
    EXPECT_NOT_NULL(config = s2n_config_new());
    EXPECT_FAILURE(s2n_config_add_cert_chain_and_key(config, (char *)chain, (char *)unmatched_private_key));
    EXPECT_SUCCESS(s2n_config_free(config));

    EXPECT_SUCCESS(s2n_dh_params_free(&dh_params));
    EXPECT_SUCCESS(s2n_rsa_private_key_free(&priv_key));
    EXPECT_SUCCESS(s2n_rsa_public_key_free(&pub_key));
    EXPECT_SUCCESS(s2n_free(&signature));
    EXPECT_SUCCESS(s2n_stuffer_free(&certificate_in));
    EXPECT_SUCCESS(s2n_stuffer_free(&certificate_out));
    EXPECT_SUCCESS(s2n_stuffer_free(&dhparams_in));
    EXPECT_SUCCESS(s2n_stuffer_free(&dhparams_out));
    EXPECT_SUCCESS(s2n_stuffer_free(&rsa_key_in));
    EXPECT_SUCCESS(s2n_stuffer_free(&rsa_key_out));

    END_TEST();
}
