/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <inttypes.h>
#include <fcntl.h>
#include <s2n.h>
#include <stdlib.h>

#include <openssl/aes.h>

#include "crypto/s2n_drbg.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_random.h"
#include "utils/s2n_timer.h"

#include "tls/s2n_config.h"

#include "testlib/s2n_testlib.h"


/* Test vectors are taken from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/drbg/drbgtestvectors.zip
 * - drbgvectors_pr_true/CTR_DRBG.txt :
 * [AES-128 no df]
 * [PredictionResistance = True]
 * [EntropyInputLen = 256]
 * [NonceLen = 0]
 * [PersonalizationStringLen = 256]
 * [AdditionalInputLen = 0]
 * [ReturnedBitsLen = 512]
 */

struct s2n_stuffer nist_aes128_reference_entropy;
const char nist_aes128_reference_entropy_hex[] =
"528ccd2d6c143800a34ad33e7f153cfaceaa2411abbaf4bfcfe9796898d0ece6"
"478fd1eaa7ed293294d370979b0f0f1948d5a3161b12eeebf2cf6bd1bf059adf"
"036bf1173977b323f60c6f0f603d9c50835b2afca8347dfb24e8f66604444951"
"53e5783fd27cda264189ff0aa5513dc5903c28e3e260b77b4b4a0b9b76e4aa46"
"e04bade7636e72397f8303437cb22be52810dadd768d5cfc9d3269e7ad4bc8bc"
"e20dabb9fcaf3aed0ec40c7ef68d78f2bcb5675db2d62ee40d8184b7046f0e0e"
"f3b247d0400740d18b795e8e9c04cc43eb138cb9eb6c46862030517d8b3679db"
"0603b481bb88d77d6bacf03a64cf82248420a95cca10e3efc012bd770dd5621c"
"233b1e550a0d1249a5bd09ccb9a88be9119258feadfc309a6ae3c340918545b9"
"9d97ce8452474bc19a4be64efd43484874074779e05ac221f19db3955ce29bc1"
"5c0ef27b53eb7903cc9e2bc709f9e885eec139ec687a3444450f0cb079ca5171"
"0e26d3e8d2fd18fe0ce2538c2ede5d61574c8227b3f82b333ac42dbdd78b8e19"
"12f68f049216e3987860651f6fd13efef184fc8fe05cac459eb3cf97dd957e6c"
"ccfabc0f847801b342774ce50d80c600af2d1f2016e1aea412fc4c60b2a041b1"
"07e192e576bb031bb8baa60b9374dcc1c40cb43ab42035719588e2afd75fc8f0"
"6129a163efde5f14067e075c4790029652a56eedf8ea4877a0ffcedd32866166"
"356ade73b8ffb38408be0537ca539b633d0afffcf2962b717ac37eb2a06ddf50"
"0b857fe137cab149e9195019732a714e25e62c946eba58dd2fa8e6c797172bcb"
"310d2e7b249ca8fdf1d4b15612f6e1f5428241c7ad777281171fdcecf7f5ed44"
"241e8fe2d6de5efb6509144c8dba00a582d1aebfabd306052747fc311d7c5a56"
"a2c100da70d8659d94a4d6a0f10594c8412c977168df242a35d5c2600a47084b"
"f5771eeacddef0c6cbfac5ac4285205f110fd6a8174ad45748a8633a28c85ec2"
"0621babc5c0ea527ca7c8d42338e16b6113b387ba888a6c12779cc127561a148"
"672df1d58510c016913fc6c42771273f7cbaeef1993dbabcd6cca26758bdb7df"
"7a9365ebb48fdd83809167cb2bfebc37b69b34595b2f8d81cff2924a70e300d5"
"954e64b6f4f1d7e0135eb2a9174612d23111329c00bded4cecf6b2b2fdfad145"
"e6495728cb28b8f64b208afa9e1012f061c790d285663f5cf0760c9f7c4bd32f"
"bd10e4b282c98b6c2e0451272a332c24f54a2a45244e9889420a48786f662aed"
"5a1cf5b5212ae2a776ae4f688ea9e6124f624c817b5e429b8cc2ad730cf29f6e"
"fcca996bf011ba139b7bd05e31c594d459685aa143e0ee46d6db0ba8582a6fd6"
"9009b2d3b9ef7fd1e925d75d6ad07d42e165310153ed1ef9e1284894e0d16575"
"13f8641a1d9cd50966b4fff6f2a5a9f67aefa8d7b5cb527d3b73338aea773ee1"
"4645aa5ebb41f27380328161864cca36055c871356316bf3773d35687fe72874"
"87e58c3c91ae0935b7935d2d0a855e795327062238180f20b02f9c9c861cbc33"
"28c5691d0c0ff0d834cb0c85a82fe561f40803f63beb3e740215e5d5089fc554"
"fd22324369fd30e2f47553c012ce2c46fd40df5fcdd737bf266cd20bcdc20a98"
"f3291f1d5fa47abf1918416a2cb78b243e614f883bda2afc10ffc1cc7f7f06a8"
"c9cbe9f41e2d81f99ca6327ca617caf836b73512d96b1edc5ae5ed56c056cade"
"47ebfc4437f769ac299f0d87069e5d6074420113761a9f9e053866581e836701"
"bcb51bc0dfae0fb04bf08face7369981d9a78bbcc0d3da2a1442d8fef756c1c0"
"b74a392be091fe00eb6a6576f027073a838308f5a5aed7fd0db47d6616cbec98"
"d39a307b956d1183f718be7d91a11891dc3fee45652edb89449d9766fc85bb32"
"5565457cf60a3aff9ea6f3dc6254a76a085ff87f1dd19127b2aeb3ac50b8c31e"
"9dfd31e3adc822b675c0a9c8702df12de4c3354ccdb5389ed481d910b3dbb51a"
"2a1b1519d22d40ef4ec23c6d97dc148cfe171fb5f8b1c305ec6d8e83a1ef9064";

int entropy_fd = -1;

const char nist_aes128_reference_personalization_strings_hex[] =
"07ca7a007b53f014d7f10461d6c97b5c8b0c502d3461d583f99efec69f121cd2"
"99f2d501dd183f5657d8b8061bf4f0988de3bc2719f41281cf08d9bcc99f0dcb"
"617d6463eaf3849e13b89a7f9805edff3ea1f0aa7ad71e7de7af3481bfeba7f5"
"7f7d81a5c72f9e3498de183329d6b2291792ac8c81e690200387305aba8987c7"
"0c70a20b690bf5d586b284aa752ec73055e039233089a30efdd6218a1e49f548"
"1fe2b0ce3a1896017e30753064e1c0e1341b673569c739a199cd218fe64665d0"
"2703e1dca9926995705229cc8a8c9d958bcdbfd5f3e09eeb349b5135686aeed1"
"9ca4b8e6cdec1ecd9546508542c84936ff2aa1a4dab969613139c01e35f36d71"
"0f533937857dc9f97fefa142c95445b484e1f259a488e9fa38a46e49d693c4b6"
"950472ba4b3b6979ba4d2a1ad51db7732eb3337b28270fdb7f99018144734f72"
"06bd36977e09cc13d7c9edc9a285043f7c00575610e9b95fd3754a4b7c561fb7"
"6dacec09cc407ddf545c4d54c77efd712f65be8ba5ecbc9fa6bdf29243eed72e"
"85facc571d2c6eb257437e1d3b77b5fba4a125606440181b8387f9a4fb1a7fbf"
"2c4e73ad2597b027dd04c6056db1189b7a0d8e9fece52237cb7fc2511509c4eb"
"717c4de30c0ac7b831807cb1fcf4ab37f1734683a723d183fcfe5fc8a4c6c7e5";

const char nist_aes128_reference_values_hex[] =
"462eaef2ff6d82aec55f451776700e4c" "010cd7c293306adbe9798f2f65bdfb01" "f6f808dd7e199b3ce8497d63515092df"
"1e574e0a9b220668776a109ecec959f5" "f47380b9e6d8ce485a5bb9f890331f89" "f2b475b29ed8aca7f3a69477212153e3"
"d63aa6ddf10dfb6934b7a745456f2056" "29c05402d0dd6ff1d171c523e6066b3d" "fb15e2dfd607439797e29f9ea9a24788"
"601d313b010af1930132417697d9e27e" "b17422b4a74cc83de34c7196cd232355" "b63cf4e0894e185eb7ef572c2adacf98"
"a7ec1f62b063acd9904d2ca4b26e755c" "b98e1a708027be7d5f0ff46f775ceece" "5b5adf71f7d8c85a011acc778c4e3d6f"
"6536d316f19bd244ca1a2deba572face" "0ce6ba1487b38261f306c84642338b53" "a19af0020f46085ca3caf34b2cb4f1f5"
"cac724dc3e214ff8d0ac4f60ee2dfded" "67138c2c7a488b2f4449b03192aa54f8" "d10073624d73847284c91b46e28b83c3"
"edadadc2ad451ea48ab9619d6c89cdcb" "24f64c09499b4803a03aadf0e34240ca" "8ac5b02284cac91bb39e14bd3d38ae2b"
"31f21cce9f11c7e9047e3ebad7c23a1b" "6b59014f0e7e8df5f7456017841e9c63" "4cfc026d6bc19e9674ec7002bf0baf62"
"d871c3f06cdf34c0cebb8b405aa79be7" "6af76a8c51f305b88249af9db4eacfe4" "ff77327ab3761736e40f79ca0a6660e2"
"9eedbc9923b20434c175c066ed3584ba" "06ebe4bd2ea20c39ef8f4f66796816bb" "497b437274f3d7cee04b163c10233aec"
"7fca6267fd42102de5baacb7b4409565" "1310719710bd2c3468f8000fad5b6f4c" "34e5d8e0f7e6c28718a5f27ac086516b"
"9948b0263f2c91756050fad1f5d7876f" "9aff44fbc0f539186d13e81a9b233786" "0a86ad5766efe6d3fa01a9ac4ec9090d"
"a022dfed4c805b8f2c15d81693edfb53" "9d4f527ab03ff0c4abe7e442572fc0bb" "5fc9cb9e3cd694c6b08bb99256062814"
"faa46432da44e336bd782edd85ccfa83" "c17b86c7fd8e5a2131f515fb0ab62c9b" "619ff6d15579a1cb4bc9c96f6be8f4e5";

const char nist_aes128_reference_returned_bits_hex[] =
"bba1ef50b4bad288897f02ac2706ee1e01488dcbe9b3d8a637921f5e788faed3b23db63d590ceaa7607a2179192bea9aeaa85d048e7e108fee666dc646af5f0e"
"b9ecf5521d38f9212578f9dd32af38089b45812ca96e661fc8e1be0b2f4b54215f52c9c93a6f76efee4521cb316378403108a6bf2724fdc93bc4d2db60a2de83"
"ce4bec8241dd1ce12d7fa18bd1a3188b43892392b7dcae7228a851afef9c9728c587167b6df28c895a67af35b6fd84ad076efcd70d1c59c49fa7c0f7ed87bc82"
"94001b011830bc6a911fa23bc1fd0dac8c0acd0e856ab4497ad072e54fe3b47bc06890e7e7babd4912af1e7da96e90523b75dd86d9a4ba4d88107de607e52534"
"d0619996c88423a740f04dfdad3bfc131bf3601fc43022e89957bf8b9a1ad8702bc8fbb2004e7ab02550777818e11f03fab48458424ae5c8cc8cb73436657292"
"a2613ddb75107ef3fe9fc392061a52ea2304af7aed6dedec3aee626e1ab2bf989ce7d6484555941e9a4013036c4605c564f17d4d1369e1e12d28b877d2125d99"
"48460543d08b3331f0c7bcf786be06a276efc757bedce0f428323d54206931f18c3c7c606c0ff8e673f3d1367c7d50db2ed002120ff05623d2deddd037c125a4"
"037a0305532b6bd2a51057962f23dbfd4660be8e5b7a448b1168be3bf8598a301fb517a4714b7826162fc0fcdae08800e967f638ff1ad1da39282d3454d93075"
"035c19396d603b52222c16af6c6bc1c07a1a518f578b59943ffad73ca14948b7a8dde117e5c571506d57fd08e3a067a2ae3bde2240c2399f160c5cc5a2f5d582"
"e17674172397369025d6b7811b69b6e62dfb8ab94852cc96bde1371fcedbe5fe31a11589f4e57183fb46883d93c647e36f70f8d5a536f8fb0d428dcfd7722e4e"
"cbedccaa88b22e39fb0e14bf15dc05e4e1b7002fa0cffe7803e3f6bcf6a03f3faa51ce5b3ccb0d341533d335e20f9f71e90f83fef06ecfe93ed056f5d6851306"
"116bd7ab4030379cd6f50e85a04182775292fa9619c38b7418a19b8e7855f29efffdf7a2b8b1d9d3d96ea85a6d56302014dd3bcbe401ada5b0e3cf2f66dce9cd"
"51e0b54c109884baecd1884f7bafc846ace216b6fd97eb1ca70b563e62c4a2f22b55561152f379326ef2999e9746f25043a02402d3e47b4a58e747c222b7a081"
"7c41adf941656cfb9f24409d6cc4d578d43930b3e23ec801a59c53d999401bc0cb3e5b8797b2770a8a8f51ff594b7b17d9e694d5e36644508d16cb2554057adc"
"ac054570b081cf53b39b0a2faa21ee9b554c05ff9055843ac0eb9031d1de324701ad4cf2875623e0bf4184de4aea20070be1cb586880ac87fbb7e414b4b128d0";

/* Test vectors are taken from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/drbg/drbgtestvectors.zip
 * - drbgvectors_pr_true/CTR_DRBG.txt :
 * [AES-256 no df]
 * [PredictionResistance = True]
 * [EntropyInputLen = 384]
 * [NonceLen = 0]
 * [PersonalizationStringLen = 384]
 * [AdditionalInputLen = 0]
 * [ReturnedBitsLen = 512]
 */

struct s2n_stuffer nist_aes256_reference_entropy;
const char nist_aes256_reference_entropy_hex_part1[] =
"c8f0c7b9bdf7e7d524c998aedeabb3b7dd4fa8f95c51b582010a5e09d0b4b1ad510302422df738fbef002a051543b4cc"
"c1a7b160c8e33a01fbd49743dc1161539390d9ba6b876fe63b58e8fd605b98617322578b17aca9db71e858b154f97910"
"d98b25eda41d15eacdecba586609d8c743704fa099ac37f9185bcb19652723d1648431a73c4399773c85caf12fcdd842"
"5fb3f302c36d0d0e28efb065df595ea69a6b3eb45622f9d14038ebcc0d4a8b0d6aa45e681edd5c506e00f0dc12775ac4"
"6440cc8c735ca9b05f261358e51b8b4f8c4bbdee9e2681c76fb552bb6b62334038bd8e0394a4d50f6af7a7a920379799"
"2ed7e6118394ce10a842d609baabfaef9d1c1fea914be4b725822f943fda023244f806a47b944ea0c1b853f36bfa24f7"
"f3fb24592e88aa2bb3921b46e198310fd269883eb68a7831e5627a5a6d21543864ede3fbc8badc1888b0daf37a97dd40"
"deda2a043d035744b5d0e696e496382ff0c01cc79c9f8f588b40d934237fdf7d0f9ea389cf28a352917c724106417d92"
"dccffb5e3cbf5e36eb1ca92db6247e1d6dc777e591893e220b5cf55c50c74bae2995affb003a8306197771737aaddf64"
"8a0a52b1e228c26be6497b5cad0677cfaa2c42a4fc429c4bade7a468ce681a732f92dcebdf5b3d9a0dcfdb5c11a830d4"
"51a2f38792fb87570747a54b7a3f5473583faaceacd70cd5b5336e8ecbbcc286627943999210573ee7f8f29437f74b02"
"77efd90bf6faab8ed0bb32f138fec4fe8afd7e1a55b2e60d5d500ebd57ed382af97d9ea89375fc56b511cb674e76e4f4"
"4256c1c6dcb9463f751d97c2b9a1df629d2f6db19dfce80da4624e5ceb2403ae6f1906f2d8e34cb015525b27bb25c262"
"8ba03c2283b97a37063a4597f7ca15fb2df7b0de1e2236b8338f14539c059d1a47a947bc9a3ef954c833fffaff8fa8ff"
"c5d3a88de9db79dd707187dfe5d35443f7eada1669d5daf39af4d78fff3fd35f0e81922a207e640cba2c9fb18280f62d"
"6e92427a94816c838ef57f9d98941ffc3cd070c76fcc19e765f9b1f9d390ec99f0b5193fd72a3d700deaeffea6c2282e"
"8e7159350759fe73e6c51ab224eda1cd769c703a42a79d3c4ce407aa99c8427f872b7c3e09559c789cb75c546ddeb988"
"db12fb9c2f1cc022768f824dfd05edc6d57184ee0e51ce8decc74c390adee63ee401a7d3bb0a91c1d50fd2239dc3fa57"
"14932f8ee3ec2119e03b65dde53c2c4156b8013c4d1c260227b240af61bbd0efedcdcd4fbc828dc688cef0b25bb12374"
"a5d063e966ebfa8bb05fc0c0625a30d0a408e5e31ec9667374ccccbcc07f6c289ecdf3deb3f784925e7e72c75105bf54"
"31d8ab37201b55662101ad235883c28ecfb5c9e3cf0498f6cd563db96f622e5656967256c7c3efc2ca3c577be02de3ce"
"a7d7b56bdf38b57d7418ae3f3a90375d7aafc3839a2956f6824d1c55d615966207a5ef31e2bf8359db1070612ad6d775";
const char nist_aes256_reference_entropy_hex_part2[] =
"f480e7c970c02a5a64b09f0473d04b658e19332634043569e24996981f7d515d326ad1129661638753d117e8d31a540f"
"0854d1a0aa78e3e60b6825d143eaa97ec7ddd1b8b85c26b625fe4da7973d643cd0629186c42928c8e46857a603e5ac0c"
"89dfbb4a10bad1c269341b7815ac1388a7d28bff8393e078d99a0cdf12d0f28a24e45441c86584829ce37d4eb3b28873"
"6d14b671eaa66e217dd973047b6180b7dbd2c29b709fce014bcfda25e269bf5a736d7154308aa0597c5f5adc3eb4cdd9"
"7c0a71a8f56ac0b5766525b0f63afe48f4a0d282adf300f9da47ac62693f0d74f6739128c61024a22f7469d822382cfb"
"d0daca073b0c1517b9d6643c518130580f254b482d4c44b735590e167b06b304e0664b8e12d9c8dd083f4b758e7b3d81"
"4441277388baf0ae4d69b0c1db2b4d767647730e10cf1191cd10fd2eba570d348e544cea0641af89418c900ccbf2ca20"
"2180dc1f5f17f5f8cbb8499e155de4bd50e0f2175041c24d1c72f654af8a08563b1c42a84c5ae126ef33e1909bcee38f"
"48e6177813ad0dd8da8506a91fe0d4e615bdd068b423050a1dfc94e1cbaa2bbeb2f92561391a4f54143ac46a74d57c03"
"f9d761f589d8e466123257d4b144e40106be6a063643547b8549733134b3375715157246a9bf9a91f854a37ce7efb3e1"
"b774616e89a2297ce5feea2f5708eb0fd21f3ae188ae25c64c8bcee73be40db2af5d8e640ccd48b8cdc7375e5c53cad7"
"3507214c359f4ab75904dd4e430ccfd484b853b40b7253d430111588410f1c9fc41e757f669d3de45a3c0efdeb250bd3"
"8364b816f4c64359e54415082fd5b04cb896bd5de5527b0930fc6a855d2a31b55cba81ab25b019adc7cc7c7a6f308c4c"
"ab2a1d12b1997f5a1b74d6608e60f09682924fcc4270fd5fab8e84f2be19306e49537a40add14ba9b1472f80a97ade7d"
"e6a8dd29ea2f9f2a4595aa1b9600831d1647f53f366724517569e2848f5a7ccb4bd2f553f83f91c14c2361cbc3ece926"
"ac25bc0603a569b90efc796aea338684d84c03240d1bb3c9d3b24627fb24235d6fb837fc382c6c949ebc911abadfe9b5"
"60fe48c071073a815ee75a6b66e0cec21fa510eb721a10cea64eed977efe89af922f8bedade893212e6a253169821860"
"7f1a2afae1e642c3348a0ee56a0f4ebf136d68f8f04de54b3beece7828aa43171d09570bb70fca53775e4770e3d4cb84"
"edab61da555eeff611c0428a25200003a5ac1c4978a766514e9222c80adda7194b8414835f0fae94264d3d81d49bec13"
"7810ed74bdb095e1a3a8a2b1fd885e21c3a23317b5a4514a9bae2d0072826bfc292a231500703ab0a1f04ce35bd3d808"
"f72592e0626539903bfe7926f2df89428ffe4eceeb57f0be46f5d4bb0ab8c70633431c70056e051b2a44a99fb2decc80"
"2b3877ed4d1b3174d36e784ad7b6b7991dd52979ca5b1c4cc5f415ea56aa78f2486e2b033570089aa0e8f5d4be3ee140"
"91d421c3eb04de94099a7467254bad70e236d5c27616f766e85b4de3965001db854e61a80bfec2eacb4ff93ecafb8b83";

const char nist_aes256_reference_personalization_strings_hex[] =
"3b8f2ed03e4c4a857ebaf4730124ae5b3ffa67e294381fe085e1d5b25bb79c228f39b9912d8bf9e84cdb43fcefb552e0"
"e4afd48a08355ccbd097bf5c87e9aa6cca5bce84b211ef0c783d7e05cd52caae4b4d83de53a84200a556b5aff5047b13"
"a1a853ffa798f93a604874d4c2c7fcf2ac4a6ed1e07e03336b7e3ddbf603c19f9d8b3041cbe3ac09e96c86c8bdebaad6"
"9367c213593e3a82059d3c80513c301f0c840c900ae8f18b5be558d1fb8bd528dbf93e6efb7f3cd8fed577a3e299bc76"
"88d9b7c50d99c926f035085a7a8f02698fde845db85088e866187407bdf75b2c6cb628d5081c859a5d738826d2e8c1ee"
"6d7621ae460ae10c8c8d0e11c80aa444e279f2cef7da2a0e52fe43edfa025c67ba0111b6a2774b0620eae65aa2bc292c"
"3dc52487f866eef27a6aaa0f3da87c09c859babbb73e1771626ca434534a66b02e561363db90798edb55cced2746767a"
"015c5a1d1f9e2aeb34713767a58d01b0055a27151bafbd0afc31fc22d765e57f65ffc282aba726a2ec5a7c36a33c0ecc"
"5235d1b8ea0e83618a755c598fa8e74d6e425f946249e80f12d85d3e1c547d5048f235687dc93c86cbb691384f889408"
"06170a3a66308cea0ab1f44e688e7a4f69a4fe435cc325dc554771b4156614c77d3c21377ca552e6d5ac9b7ffb52f1a3"
"767fa94128aa6e71dfbfb4c16be33c48941c5ccbf96e8094365f581810ce94b3feb8960b99eb925b0c6184db40343849"
"806f8ff25ac8c4d61fe8cc895f5c5d2e153701b5c2cc8ef6b4ff7ec5f6273b285695000016e7d5a6145f4f98f4a42bf9"
"dfa7445d60ac908bb031bcb4f9feed626afab1e4aef021862e1fcdb34fddf9028b6226dfb11f677dca420ceb11930587"
"b1805d90d9e43a9e509f5f71bad514b548808b993cfaef7a69279239e687f4cbe3a6ba579e11a4fa2b2450f82c2fd31a"
"27b9250c01189a8a675d597cd2e476d11f4feaa29ce2d9e729eeede42d9b78521937d240b12db5493aee96b84102cd9c";

const char nist_aes256_reference_values_hex[] =
"ac5ab81937daeb6772799c778ff0d3a2" "0eebb4180d8410794daeaafc1847c923" "70c7d3292e845bdf82fd274edd68a653"
"5389de7c7ad334241af4b0fd92751459" "75c74d6c01f589d3ad73a3a5b623e7bb" "d6c396bf4a3e833cd2d606fce7d81981"
"8b06d07034ff5a65b07ea9b5b27a4218" "0ee02cd9df5f2bd1ada6f1f9ba7f6056" "8965850a9a42cb15dd40acdc5a9fb677"
"860be14f13822b3622b859718637b92c" "9d344fb6d571418dbbfe63bed5bf948d" "3f86d6e5294dd831d702c43b8ef27b48"
"71cf2dede759e35e9983268f1ccb3602" "4a656c7375adb348950a73236fd94f3c" "157ecd447d923208706e95561b3d882e"
"38d40b4342fb5c02fca2fc2a7178348c" "65a6f202aec5a1fcdbdcf1cc456e1ec5" "1271bbfb300f823f19fedd138118fc60"
"b1fbdde650b4de3c8239c9d109f16080" "78151d8dba8d945a0feea6b2e1adec27" "a3da7d1591fa63595a3c4cf7c4671bff"
"103a2e797ebe8f8fe6e8f9d9fcecec37" "8067a5626c79baec12ba054032d6c5a7" "1f7232216822ed37039b6e46db4d81d5"
"1e7662e3820a927086f719f8893c29f5" "3d8195aa8d54d162d3b8c7dd2194c9aa" "8b3b81b54c750c1f795dd6f009b9f0f9"
"ef3a697359dab04f0c312584002ff9ac" "aba26d5d26ee7f035d3f87bf5886ebc5" "a14740caa86474ad9e2b843f49dcc482"
"3e21b0a09757f77bc9f9b53f41e771c4" "bbb03998195593d46bdbe7b1be8533e4" "41ccfeb0a667ee27ae8370efb2afbd9f"
"e0eb76b547dcc2369fc1b4eb6a8715a4" "1c4a394a564ce025ecd6278a7a314403" "3e37edd1aeb247aa4a6116b54ba29dae"
"b2d0d0467e86dcc857c398aea779d92f" "695104cd3099d7f3320ee44505729da5" "55b9cb44f0a6d2b4a5ee6a8aa7d5c7c1"
"8ccfee961eb844dd8dd8e206bafd2d10" "ea3a81303d10eb79c8b26cbb42969a4d" "cad6784d017fedabef3bbf374b06ac2b"
"5814cdfa83e59a26c108caa986da3492" "503e3029d555fb6bcd4be394d8ed4638" "969f3ea8c1ab6986630149eff81d2162";

const char nist_aes256_reference_returned_bits_hex[] =
"338da59350a72bba94b217b99ff813fafa85f31fa7e991d4350d6fce39471aa249c6a9e7d189649ea6770a15be302b943ad403728b7387f5984c9bfb82597771"
"be9333140428553231505e8ce3f789f2860f44647d97239c0d34cee98e0e4f5e5a5eb296d4cec508624913080a1b44990993a2ae63f61124c4d8184f191ca8ae"
"cdecc083b5c4bd38b573c5e109fc1cbf2dbc92982ed6d24cf4d2cb06383ba27d51dc064a8cf42205420d1c62505b987c774502b93e837485284a137cf2380872"
"ab1478cc75bbfdc930fefeff1e6f8e7b822213976fc556ee7f71550d128620766d8353b3c54c59934e7fa57e8b857c7daef8e9d82705fd1fec7b19d5c3b5af4f"
"f64d6ac3fd9beda9ea4b3fc2921e967d126ab4e747eb4f29bfd949f94119271052ff52501cb45af6bf9499ef5926423f61bd4dac0b28fc95aa886c8226ea27b4"
"45e3bfafaa00941459b373aa00e6096b7527110f4c6e4e7d6661829dfe4ad83ab23a5779dc7f8116b73b929fc3da43ad346a3e11364e1b453e66335b5cbf59b1"
"8bc98d27050e713d19551eadae19d14f3b1304aa6f736d9bec6c7cc90c85412a4e6a7218b8a7ce46b1cb93fa1b296eee789aae0cb2a58fe7a80e26f0a1018dc8"
"794128d681d355336148eeb4dd882d76ef984f2a8ceb4b451e9b37beac0fb50247bd595ede2de000f4397988d3f52e0b3b293208c16b5f45d6032bc5ef20b3c8"
"3571383b971291e37616f1c6af623a1d576cc5f95090563654420f184fc6663242aeffb06052a29e84380db38d9f3ed09823dfef1774c14120fb010600b7b274"
"b7723a01d35011a9a8e0e82a8ade37d5e992d8cc5390e2409e185a1bcede39b742fa1fa541572aa36b16be410f3ca0ca853ffd7cea2996e852b888fe9b1263f9"
"0d42ad75a67008674be7d81bb2ca9f0625b55ea37e1985d3a27cac38e347824ff03caaaeae9b646a220a8a672cb28ba869d0f53e3317be00128fa965a8ea7b39"
"d5be1698e011122874ea19c562859e552c68d2734a39f72d6f8eca8ce30916504bf224670f9a7b6afb57830a28fec0fe818df449f5e6eb8b49a3397df4bd3506"
"c834a90e72a5ec0148942c9fbde8b90f058866ac3ff8cc854bda3d33f6072bc0e5a22c7d0cd801f091276ed7b7e3d6495df9546b9fc45e46aa6b89d3dda207cc"
"6553c630a07ddf7dc2110c3aa3c5ac0c488a0345e07571cd71df115ba37ea4676935be72a6033aeca7ac6fcce5654dae38f5777b5cff34b156539b42ed6dc93c"
"ed703d9273bb9462ac400ee8d587ea3c4d6c27aa014defcb6ca6fe885272bcb4b6ba0822f42941071bf635b41d997c631b680d91b23ee48351041dc274900821";

/* Test vectors are taken from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/drbg/drbgtestvectors.zip
 * - drbgvectors_no_reseed/CTR_DRBG.txt :
 * [AES-256 no df]
 * [PredictionResistance = False]
 * [EntropyInputLen = 384]
 * [NonceLen = 0]
 * [PersonalizationStringLen = 384]
 * [AdditionalInputLen = 0]
 * [ReturnedBitsLen = 512]
 */
struct s2n_stuffer nist_aes256_no_pr_reference_entropy;
const char nist_aes256_no_pr_reference_entropy_hex[] =
"22a89ee0e37b54ea636863d9fed10821f1952a428488d528eceb9d2ec69d573ec6216216fb3e8f72a148a5ada9d620b1"
"a5ca32ff18305555d32e270f170529232c458779eaace221ac4958b4226df8189e42b0844fc765751a6291a60a35d8b4"
"2e90b2daffc3ddda438c38c1bdd6e07d78c862225d9d10b50a4d8e3e32cb63e28101c06dd20e2d174d0f4ea1bddee40a"
"8ab4fb1ba83e1e4e7f8ada8475bfa326315ded596e21ab804a90d50b2355d4b96c8d37ee0628f8f2c2a0245255a04bc5"
"297137ef2d5704ec08c8f64502aadb6920027089e710b3de3174b4aaf756b7a0b1087195c71428f34112730d10d3156a"
"2c3a24013a7c8b64238507f45127ddabf638dd69c89f268bb41f20f6edbf14157488072c171a1c99e7e05fd51541df31"
"2558704be32a8df433d8768cbd5574c24dd09de31564b9a0f4495fc1ee551e448df4fe8b1459d6b2b6144e1f4a1090cf"
"04d8aca25424af21b3e4449638d31e0d80a3ee4572788ca86640f9b87e4e07d9f755fc2e666c59b0a95fa1ee7dc47ede"
"a0a51c6e8011f26db53533e6be8758dd7cd3c6cd00ceb4f429acd40b193beb1889136618c7826acd0b7ed10eef0551e5"
"13e7f80bb83f94453bb5859079206d7c76441488a3044f20b0eedc5d06d3d8f8a633e80cdd6104d8ae5154cece908475"
"597a5ca7e1deb5433e0a7c6b188530e2166f3c8c16ccfc7578c8d9931d70b4a333a536abdb0725b6c86fe3d2b2974e17"
"32758241cc572bb88219e9c8280c3d99fdae0cd8e878f8c0cdf112f17cccb0121fbfb0859d27a0734da2e8c6de4cd80a"
"101f19ed66587416179baa901d8b888b75770ffe679117f10f25b46f659a570ddbdef085578ded5e0d74fada6837fb5f"
"224809c43bcdb46c52fe3098cc2d88d0d26c34e76e58f97047027adfe93f8bfa01c55d5b3c267bc60289ec82d2fa21bc"
"4e37ee8649a86dd0bab8785a1e3acbd2c3a57ca346d0e31476490e49b588b928232dfa50cb1d96078f7068561b97e2f1";

const char nist_aes256_no_pr_reference_personalization_strings_hex[] =
"953c10badcbcd45fb4e5475826477fc137ac96a49ad5005fb14bdaf6468ae7f46c5d0de22d304afc67989615adc2e983"
"f42a3a32dc92a3eeff658c349eb2e181564458c202aa922ec4364e3a93b2ebdfb58ef78fc7237b70d8a261bcf30bd1b6"
"f349ed3b779184b8048f833e79751574c485de0b8f6ec73bf08b3ea4b82eeec4e736ce5a8093f96b4d7c7ce80f5cf606"
"b838dddbbd18f37c352df301a07986fb4cce42d8f914547f49db31721a8bf4a4d45256f1a404994d3088ba095ad88c92"
"e470987f1799ccaec5d2e73b0c2df260d1c19ff075bb97a65ccb8cd7dc94637ca7a9f46948afc6cbb5e450946468d79d"
"88692bbedec9fb0fa2bd857341328a0eea7af184c79990e0714d41d84a1197155336f89243fab6a30bc9e34aca446a6a"
"442c2e1d96fe08d89054b63a05b7122ff7936f837f4ac95d8dc3a1aca3e3680b56abb0e022fd0be9d0c11f5acdfaa8b7"
"0ea4210396f98612261f80777d3ad5166f7b60c0bf821fd105ebd161ef1c1c5db911bc59bf29441f13228e800ad1099d"
"102cd6ed39ce048b3cac4d535989bef8d4b51311948c86cea421e268d36bdb03ba1229026081783f8c05e2e73cdd3e72"
"0abf501a537111f992af58a110749067b2b4765d37f0fe951cfa6eda03d410027df034e37398dfb64d50da515d3868a7"
"80c2283df1561974506872ffc33bc7320ae2ac2d31e32d9c04bb75dd8a8cfa4c89597c9078622eb4d2900466625c0c9e"
"628cb67176e187ed101f9f72a52368c2475b38e692297221c24ce95f2801fab1c29a4085664be4f751b5a64d787fce29"
"ffebb3da7565946ed38a4d5c850c068f0cb10f6ce503440006f972a366dd61c3e9e1b00c6566baf8eebe0fc868ce363d"
"1bde6bbdcce020ece37fe2931a70a88c5c36b8d29cb07590c9dfd23f8da8677646046dfeefeb17b45a09e621e263d406"
"61334cdc8735332925221a6318987403a4c1c936c0a8066cbfbb1a84510bac2bb37ea52d6ba9f4e1a93269473f4566cb";

const char nist_aes256_no_pr_reference_values_hex[] =
"d81c6c3ee1a8effa1772c6367112fcbc" "8c960164b4afeffe826fb7d9160261e3" "55f1f21c57581386cc681ba2253a4122"
"59ac44c1bf423471136205948c383c8c" "2dd393f66078f4304a3416520418485d" "4bb37755acc02bf44050ace0ef8768b8"
"14570dfd653bfe08d1d1c7c7c7842782" "f8c796a139a78a9c678445318d53525f" "c6604f06f047a80dc8a750c08044dd47"
"cabf62d5958a4bcb238a6bd57a7ef2d9" "349105be229c8af6a6603ab972810f92" "e764ae76ac6b31a1bcabb8641645104b"
"64c18636b81dc44c2554d61701bdf779" "1421f0d4da0828d4f66621c3060528d4" "343f6cd1a9c0d5cff72f7c01a04cac14"
"55defc746346804e3d8b4911aa0380d5" "d5b310ad91bf1d982d06a8d064ce783c" "4170cfe4385ce415e71f2672bda770c6"
"a93f4da10102f72fb777a4cbf2ec0df6" "18b9f7e519c09fc98ad5d686cb44a530" "d72d15a845596a4d2d9c43d6a3138844"
"3c2443bdeee337db6bdfdae0021342cd" "43e1673beb102480abfb29089bfe21b0" "481918557651a3f6bb1aa9b9476a3a44"
"41614cd090a5388656d9c667a6de5a19" "e4aba9bba8c333ad09a4f740b9f65363" "1b581315ae5fec8ac9a01b6dc90f2103"
"a9a3df25995ff11a32a37b11e6aed95c" "50f8bfac45b1392467e0ed28a567bf4f" "d899e4203509e657796be2dccef76ef9"
"c89c49f194c32176cb5d123aa5cd7707" "65972879c31d461a64d5dadd0bcd640d" "ece1e8cfc7bf2cd917dc468830043e3d"
"af45f3caccca6ef0cdb5bb05d33523ad" "ac4751e98b1ce69d6a6e41f2718f13d0" "63cb2ff204cc8eafa0106ef906fd5986"
"405f4343054d7dd23268009c75fff8ec" "4b5ddb4783c25903fd29b0560248ad93" "612a110966961729fa1bbff25f113f62"
"35a1336fe46b46068922ff2d459fc034" "a121e96fce40c3b6620c8ac448db12c5" "d82baf1b1c938ffa6c5732dbe0355305"
"e2335cb797124892f7e0f49f51d4b1b4" "c169ff83c41d1a2dbc6796abf092b678" "78263f1b7558bbff9c25f1dfd6b837c3";

const char nist_aes256_no_pr_reference_returned_bits_hex[] =
"f7fab6a6fcf445f0a0434b2aa0c610bdef5489ecd95414634623add18a9f888bca6be151312d1b9e8f83bd0acad6234d3bccc11b63a40d6fbff448f67db0b91f"
"00851cac3204326d97b5f26cd0bc05feafc34f56b5b7def2640bf5a12da0090d85320f3132fe7212c86d65f3b938366eae25cd9233c0f9941a70f99e795cde4c"
"847f61148daa5d8290dae7f7291bed58a1a4a762c81d73eabca91542a5ae2200e18afc9397a1401956926826f65da3470b40fa9147842bb49d4e0d83bf77cd31"
"0d55defbb1138ee33557c7f92504d0cd325140c088035044b3fb1c2f6469d8505e97e51d0dc97798d55b35f5b77e8ad24dd42bb9d76f9d10227ae4f05d09a010"
"557416003e926fb5fbaef50bd48c265f74bb85a29502fd0153240b88ee5b95badce5813c2ab26deeb3a5bb9d9f01852223864b55266210a4be24e4e9c02ef32b"
"e957b7171779c4699ff4c3b74274c28526106946be77a32fe696ef41aa89735078215aab201819099d610fd5680b51982ee832df561ae97cca2564f9595b4c4b"
"b7f5d4862b47419974ee09a22c1c5e0ea5b0bf1f2e1292321e864d9d2edf3e36712da89ba4557cdedf03c6a396bc3b84c4a6e664d6cb8d94d861fbe472f2ee08"
"c965c621a3ab4b375854d4c2d52f28debc07f7cfb7600489ebd9c7b64b4275577474be070950fca5628f128a8dddd9240a435373951d9a6252b52023010f6bdb"
"b5d44cf219e26fc314728695cf08313c2ce4d05c9cf7d446c507550b462c5d313b6ceb2754e2570d37538df9be45d71f2ca9c8e24b8075fe6c1a44ceede84a5f"
"b4b41afe5acd666be67f9dc45209f62b0a450a16f39ee2fb28ec3628b809f707f09e5e6d7badc1a5e7a2c5ae8b8fc57588ef110aed157c8d84c8b4bedb435451"
"c1b9226e7718addcdddba21d7b5539b4464775388034b5ff17f8b512c65725ceda4a20ff9435a3af062082bcfaf29ec1ab8f42c72856ef59d881df85d465c14a"
"f6ff29504dd7ae63d6016a62d77ed01486d022e14e2b7281956aa2f9d570da3a3eec8a744529564f55608905b09a08fa781cda39836207f6f5c165d27153fcdd"
"7f613844a6e10636fb27d8b146257d10932c37c7616099893928d2d458f294ae165def19f7175e798c0dced4ab7d96def88cd653b3264f41e756a043af6f39c2"
"48a51fb3c35b313058987bc10f6723ae5df051e180bf9b5b0fd8b4c4f12ee457f4d17681381865797b2f761fb05f12e6a9eb18b1f95d639a4af5b1613168c1fe"
"8bf9c263c12a19c50525fb70cfe56980b26957e5c295f7546244ce6b7b1b90b24ce3cffc5536e96d973b192a77f878eb5e6987e1055475a0abd00312d7a65dd3";

/* This function over-rides the s2n internal copy of the same function */
int nist_fake_128_urandom_data(struct s2n_blob *blob)
{
    GUARD(s2n_stuffer_read(&nist_aes128_reference_entropy, blob));
    return 0;
}

int nist_fake_256_urandom_data(struct s2n_blob *blob)
{
    GUARD(s2n_stuffer_read(&nist_aes256_reference_entropy, blob));
    return 0;
}

int nist_fake_256_no_pr_urandom_data(struct s2n_blob *blob)
{
    GUARD(s2n_stuffer_read(&nist_aes256_no_pr_reference_entropy, blob));
    return 0;
}

int check_drgb_version(s2n_drbg_mode mode, int (*generator)(struct s2n_blob *), int personalization_size,
        const char personalization_hex[], const char reference_values_hex[], const char returned_bits_hex[]) {

    DEFER_CLEANUP(struct s2n_stuffer personalization = {0}, s2n_stuffer_free);
    DEFER_CLEANUP(struct s2n_stuffer returned_bits = {0}, s2n_stuffer_free);
    DEFER_CLEANUP(struct s2n_stuffer reference_values = {0}, s2n_stuffer_free);
    GUARD(s2n_stuffer_alloc_ro_from_hex_string(&personalization, personalization_hex));
    GUARD(s2n_stuffer_alloc_ro_from_hex_string(&returned_bits, returned_bits_hex));
    GUARD(s2n_stuffer_alloc_ro_from_hex_string(&reference_values, reference_values_hex));
    for (int i = 0; i < 14; i++) {
        uint8_t ps[S2N_DRBG_MAX_SEED_SIZE] = {0};
        struct s2n_drbg nist_drbg = {.entropy_generator = generator};
        struct s2n_blob personalization_string = {.data = ps, .size = personalization_size};
        /* Read the next personalization string */
        GUARD(s2n_stuffer_read(&personalization, &personalization_string));

        /* Instantiate the DRBG */
        GUARD(s2n_drbg_instantiate(&nist_drbg, &personalization_string, mode));

        uint8_t nist_v[16];

        GUARD(s2n_stuffer_read_bytes(&reference_values, nist_v, sizeof(nist_v)));
        eq_check(memcmp(nist_v, nist_drbg.v, sizeof(nist_drbg.v)), 0);

        /* Generate 512 bits (FIRST CALL) */
        uint8_t out[64];
        struct s2n_blob generated = {.data = out, .size = 64 };
        GUARD(s2n_drbg_generate(&nist_drbg, &generated));

        GUARD(s2n_stuffer_read_bytes(&reference_values, nist_v, sizeof(nist_v)));
        eq_check(memcmp(nist_v, nist_drbg.v, sizeof(nist_drbg.v)), 0);

        /* Generate another 512 bits (SECOND CALL) */
        GUARD(s2n_drbg_generate(&nist_drbg, &generated));

        GUARD(s2n_stuffer_read_bytes(&reference_values, nist_v, sizeof(nist_v)));
        eq_check(memcmp(nist_v, nist_drbg.v, sizeof(nist_drbg.v)), 0);

        uint8_t nist_returned_bits[64];
        GUARD(s2n_stuffer_read_bytes(&returned_bits, nist_returned_bits,
                                     sizeof(nist_returned_bits)));
        eq_check(memcmp(nist_returned_bits, out, sizeof(nist_returned_bits)), 0);

        if (mode == S2N_AES_128_CTR_NO_DF_PR || mode == S2N_AES_256_CTR_NO_DF_PR){
            eq_check(nist_drbg.generation, 3);
        } else if (mode == S2N_DANGEROUS_AES_256_CTR_NO_DF_NO_PR) {
            eq_check(nist_drbg.generation, 1);
        } else {
            S2N_ERROR(S2N_ERR_DRBG);
        }

        GUARD(s2n_drbg_wipe(&nist_drbg));
    }
    return 0;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Open /dev/urandom */
    EXPECT_TRUE(entropy_fd = open("/dev/urandom", O_RDONLY));

    /* Check everything against the NIST AES 128 vectors with prediction resistance */
    EXPECT_SUCCESS(s2n_stuffer_alloc_ro_from_hex_string(&nist_aes128_reference_entropy, nist_aes128_reference_entropy_hex));
    EXPECT_SUCCESS(check_drgb_version(S2N_AES_128_CTR_NO_DF_PR, &nist_fake_128_urandom_data, 32, nist_aes128_reference_personalization_strings_hex,
                       nist_aes128_reference_values_hex, nist_aes128_reference_returned_bits_hex));

    /* Check everything against the NIST AES 256 vectors with prediction resistance */
    DEFER_CLEANUP(struct s2n_stuffer temp1 = {0}, s2n_stuffer_free);
    DEFER_CLEANUP(struct s2n_stuffer temp2 = {0}, s2n_stuffer_free);
    /* Combine nist_aes256_reference_entropy_hex_part1 and nist_aes256_reference_entropy_hex_part2 to avoid C99
     * string length limit. */
    EXPECT_SUCCESS(s2n_stuffer_alloc_ro_from_hex_string(&temp1, nist_aes256_reference_entropy_hex_part1));
    EXPECT_SUCCESS(s2n_stuffer_alloc_ro_from_hex_string(&temp2, nist_aes256_reference_entropy_hex_part2));
    EXPECT_SUCCESS(s2n_stuffer_alloc(&nist_aes256_reference_entropy, temp1.write_cursor + temp2.write_cursor));
    EXPECT_SUCCESS(s2n_stuffer_copy(&temp1, &nist_aes256_reference_entropy, temp1.write_cursor));
    EXPECT_SUCCESS(s2n_stuffer_copy(&temp2, &nist_aes256_reference_entropy, temp2.write_cursor));

    EXPECT_SUCCESS(check_drgb_version(S2N_AES_256_CTR_NO_DF_PR, &nist_fake_256_urandom_data, 48, nist_aes256_reference_personalization_strings_hex,
                       nist_aes256_reference_values_hex, nist_aes256_reference_returned_bits_hex));

    /* Check everything against the NIST AES 256 vectors with no prediction resistance */
    EXPECT_SUCCESS(s2n_stuffer_alloc_ro_from_hex_string(&nist_aes256_no_pr_reference_entropy, nist_aes256_no_pr_reference_entropy_hex));
    EXPECT_SUCCESS(check_drgb_version(S2N_DANGEROUS_AES_256_CTR_NO_DF_NO_PR, &nist_fake_256_no_pr_urandom_data, 48, nist_aes256_no_pr_reference_personalization_strings_hex,
                                      nist_aes256_no_pr_reference_values_hex, nist_aes256_no_pr_reference_returned_bits_hex));

    uint8_t data[256] = {0};
    struct s2n_drbg aes128_drbg = {0};
    struct s2n_drbg aes256_pr_drbg = {0};
    struct s2n_drbg aes256_no_pr_drbg = {0};
    struct s2n_blob blob = {.data = data, .size = 64 };
    struct s2n_timer timer;
    uint64_t aes128_drbg_nanoseconds;
    uint64_t aes256_pr_drbg_nanoseconds;
    uint64_t aes256_no_pr_drbg_nanoseconds;
    uint64_t urandom_nanoseconds;

    EXPECT_SUCCESS(s2n_drbg_instantiate(&aes128_drbg, &blob, S2N_AES_128_CTR_NO_DF_PR));
    EXPECT_SUCCESS(s2n_drbg_instantiate(&aes256_pr_drbg, &blob, S2N_AES_256_CTR_NO_DF_PR));
    EXPECT_SUCCESS(s2n_drbg_instantiate(&aes256_no_pr_drbg, &blob, S2N_DANGEROUS_AES_256_CTR_NO_DF_NO_PR));

    struct s2n_config *config;
    EXPECT_NOT_NULL(config = s2n_config_new());

    /* Use the AES128 DRBG for 32MB of data */
    EXPECT_SUCCESS(s2n_timer_start(config, &timer));
    for (int i = 0; i < 500000; i++) {
        EXPECT_SUCCESS(s2n_drbg_generate(&aes128_drbg, &blob));
    }
    EXPECT_SUCCESS(s2n_timer_reset(config, &timer, &aes128_drbg_nanoseconds));
    EXPECT_EQUAL(aes128_drbg.generation, 500001);

    /* Use the AES256 DRBG with prediction resistance for 32MB of data */
    EXPECT_SUCCESS(s2n_timer_start(config, &timer));
    for (int i = 0; i < 500000; i++) {
        EXPECT_SUCCESS(s2n_drbg_generate(&aes256_pr_drbg, &blob));
    }
    EXPECT_SUCCESS(s2n_timer_reset(config, &timer, &aes256_pr_drbg_nanoseconds));
    EXPECT_EQUAL(aes256_pr_drbg.generation, 500001);

    /* Use the AES256 DRBG without prediction resistance for 32MB of data */
    EXPECT_SUCCESS(s2n_timer_start(config, &timer));
    for (int i = 0; i < 500000; i++) {
        EXPECT_SUCCESS(s2n_drbg_generate(&aes256_no_pr_drbg, &blob));
    }
    EXPECT_SUCCESS(s2n_timer_reset(config, &timer, &aes256_no_pr_drbg_nanoseconds));
    EXPECT_EQUAL(aes256_no_pr_drbg.generation, 1);

    /* Use urandom for 32MB of data */
    EXPECT_SUCCESS(s2n_timer_start(config, &timer));
    for (int i = 0; i < 500000; i++) {
        EXPECT_SUCCESS(s2n_get_urandom_data(&blob));
    }
    EXPECT_SUCCESS(s2n_timer_reset(config, &timer, &urandom_nanoseconds));

    /* NOTE: s2n_random_test also includes monobit tests for this DRBG */
    /* the DRBG state is 128 bytes, test that we can get more than that */
    blob.size = 129;
    for (int i = 0; i < 10; i++) {
        EXPECT_SUCCESS(s2n_drbg_generate(&aes128_drbg, &blob));
        EXPECT_SUCCESS(s2n_drbg_generate(&aes256_pr_drbg, &blob));
        EXPECT_SUCCESS(s2n_drbg_generate(&aes256_no_pr_drbg, &blob));
    }
    EXPECT_EQUAL(aes128_drbg.generation, 500011);
    EXPECT_EQUAL(aes256_pr_drbg.generation, 500011);
    EXPECT_EQUAL(aes256_no_pr_drbg.generation, 1);

    /* Test that the drbg wont let you use dangerous configurations outside unit tests */
    EXPECT_SUCCESS(s2n_in_unit_test_set(false));
    struct s2n_drbg failing_drbg_mode = {0};
    EXPECT_FAILURE(s2n_drbg_instantiate(&failing_drbg_mode, &blob, S2N_DANGEROUS_AES_256_CTR_NO_DF_NO_PR));

    struct s2n_drbg failing_drbg_entropy = {.entropy_generator = &nist_fake_128_urandom_data};
    EXPECT_FAILURE(s2n_drbg_instantiate(&failing_drbg_entropy, &blob, S2N_AES_128_CTR_NO_DF_PR));

    /* Return to "unit test mode" and verify it would actually work and that was the reason for the failure */
    EXPECT_SUCCESS(s2n_in_unit_test_set(true));

    EXPECT_SUCCESS(s2n_drbg_instantiate(&failing_drbg_mode, &blob, S2N_DANGEROUS_AES_256_CTR_NO_DF_NO_PR));
    EXPECT_SUCCESS(s2n_drbg_instantiate(&failing_drbg_entropy, &blob, S2N_AES_128_CTR_NO_DF_PR));

    EXPECT_SUCCESS(s2n_drbg_wipe(&failing_drbg_mode));
    EXPECT_SUCCESS(s2n_drbg_wipe(&failing_drbg_entropy));
    EXPECT_SUCCESS(s2n_drbg_wipe(&aes128_drbg));
    EXPECT_SUCCESS(s2n_drbg_wipe(&aes256_pr_drbg));
    EXPECT_SUCCESS(s2n_drbg_wipe(&aes256_no_pr_drbg));

    EXPECT_SUCCESS(s2n_stuffer_free(&nist_aes128_reference_entropy));
    EXPECT_SUCCESS(s2n_stuffer_free(&nist_aes256_reference_entropy));
    EXPECT_SUCCESS(s2n_stuffer_free(&nist_aes256_no_pr_reference_entropy));

    EXPECT_SUCCESS(s2n_config_free(config));

    END_TEST();
}
