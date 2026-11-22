import fcntl
import hashlib
import ipaddress
import json
import os
import re
import selectors
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import zlib

COMMAND_LOCK_FD = None
LOCK_TIMEOUT = 15.0
VERSION = "1.0.0"
TABLE = "obhod_ddos"
CONF_DIR = "/etc/obhod"
CONF = os.path.join(CONF_DIR, "ddos.json")
RULES = os.path.join(CONF_DIR, "ddos.nft")
SYSCTL = "/etc/sysctl.d/99-obhod-ddos.conf"
UNIT_DIR = "/etc/systemd/system"
UNIT = os.path.join(UNIT_DIR, "obhod-ddos.service")
NFT = "nft"
SYSCTL_BIN = "sysctl"
SYSTEMCTL = "systemctl"
SETS = ("syn_flood", "conn_flood", "udp_flood", "icmp_flood", "port_scan")
MAX_OUTPUT = 1048576
MAX_RKN_BYTES = 4194304
MAX_ZHEX_CHARS = 524288
MAX_CUSTOM_ENTRIES = 512
MIN_V4_PREFIX = 12
MIN_V6_PREFIX = 28
MIN_MANUAL_V4_PREFIX = 8
MIN_MANUAL_V6_PREFIX = 24
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
PROTECTED_V4 = (
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("149.154.160.0/20"),
    ipaddress.ip_network("91.108.4.0/22"),
    ipaddress.ip_network("91.108.8.0/22"),
    ipaddress.ip_network("91.108.56.0/22"),
    ipaddress.ip_network("1.1.1.1/32"),
    ipaddress.ip_network("1.0.0.1/32"),
    ipaddress.ip_network("8.8.8.8/32"),
    ipaddress.ip_network("8.8.4.4/32"),
    ipaddress.ip_network("9.9.9.9/32"),
)
PROTECTED_V6 = (
    ipaddress.ip_network("fd7a:115c:a1e0::/48"),
    ipaddress.ip_network("2001:67c:4e8::/48"),
    ipaddress.ip_network("2001:b28:f23d::/48"),
    ipaddress.ip_network("2001:b28:f23f::/48"),
)
RKN_SEED_ZHEX = "".join(
    (
        "78da6d9d5bb22d298ea6e792cf659ece1dce54caea21323b7208f5d2d6736f4712d22fb1ccc24ed8fa36e05c851002fe",
        "ef3ffeb7fee3cf7fffa33df3a9f979ff99cb3ffe8b7ef5b57f55fa55dab3fafe99e9674f4fa29fe9fccc25dbeff4a6a7",
        "be167cffeed3ffce695af2a99627e7fafde1fd677903aa8ada7ad678f25bfe5924a1319f39bebc0c25f3fb147e7ace07",
        "4ab57f7e65b10fefdf23fc9e3e7ccac90748357c20d518a5bd21ca97f59ca7e5f243e30d91460ff94ed9a7b2eb238085",
        "e0fbc69b226801e47240f95af1ab64aae77fe6c1a4d6a797a77f60299879036a058af3b55efbfeff762e0fb05c5a606d",
        "67e107fbe2a6c866f846db5570c7ad2fb0dd53a5e3eddfe32b4da54a999ea4ae254a633cab612d7ce0eb67a7f63799f5",
        "cbcf7b917a9aeceb346bd75eab9217f93dc3efa4851790d30050b4c9e967cbf0337f5de21b59f5d48a92942fb45bd0a1",
        "ef43f322dfe8e23a10d4ac593fb2be4f3d2b0790f2ebc886960a815c5d2a5fdf9fee77a25a71c065e52365b70f0629bb",
        "c21da94f7179fb7a42fa728ba9701f42d2a9dd27822f150fa6cfedf85a21005f4b1f98af4be36bba2e0388c1ee9218e3",
        "1ba9d5e56b8500eb99e1ef21df2be63bb643db65c1343f29d83a86f8409f21c4c801cc378219d250812c247fe2af62d6",
        "36e9ae79378184f7682bef16a38a12f5c70abd3f955de4004cf0ee84f3bb3fa4a3ff233bd5a41351ddb2e193ba67ccf2",
        "efa2a2b9ee9968f7de93e8065fdfec18e1cb7acb082a65d662ac4c927bc9c03792f2ba502d37aa2c090da9c03ce82b7c",
        "2a17ca23a25c00edf1fed416c05801a4b75ca45ee48a957b24750692b1fc5fcd9aacdbf5fc758b64e26e939245a950d0",
        "4e9fa84672298eecea7291c649f704a99ffcf9ea7924cdcd46e975d13ed587f3a7b1caae550cb165c9a04116509f174a",
        "d0848761eba4bab516ec5769cfa8d595b615d75b7719bede3a01ec067d79b44d215aad89c18e56b30b4368aa84315265",
        "d46ef2e56f9928347264a1119d8e0e9a2a560e59cfe8483e152e24bda7569fced65c7a2024681d993ab708f94674f856",
        "4a506304f2fe9c0f93b706eb5189d14825f061d6853e752a854ce6588f9be88c0da886a4548f3190538f61f2995b0415",
        "13da8724557f0e29a66e1dd442db6e9262a0198bf29179854921971b559f78ed3fd1bcd06e17ccfaeeb9a1a93e1d645d",
        "e493a42e5e23c17da150e7adba8ad9da56992ead8356d6b6d9a816ace34d46e240c3d0a491d91ca04c5998dda561c477",
        "9127dd724e339aab964dd24baa9aa2dd78b31e41f0899ac693ee2b9d4548b6eec364ebff1fe80abad4db5432b2b50093",
        "296b080b331be519c32c529bf44bf9fd56152f84c8efeecb8e7c436e86dfba441432556c183883db48be226517662f34",
        "a74b87d7c2137f4f03a4ae2c57c46f487dff55aba90daa4a590545ba8485588ed40e1ffe7e37faddf5f710616e31e670",
        "2df4913d2dfaef24d1209791ad430c97bb2da8a18db690d8e22c650c94bfb48fba2ba4f28251c27c2b8d656ab600d380",
        "19ece93741f3134af87522be7608c1c816b475b6a30c1f446b7a0039dbf0f8d056d8749cf16f5114056c35efd3469228",
        "0d404a24a546f2cd0b173a93ff465f3f3715652bc76fa3d5adae670efbf414188c84f65ae2b5826c7577f36addf9a0b3",
        "1c50a48b8e433e9901edf6e998cfd7017ad38ca6d468c50d1d3f7d63670b3610231bedb6dbb2dbb38aed4988ec0dd9b3",
        "dcdcd86336b0031db42748c7c6a409d125f7299fd391ad6ce0406566ca05a0946b60d3091c668b1acab1af857b08f6e9",
        "063a9b1db667eb37e4ee13ca2154294e2833ab6a9351d4dc4860b66c92eb999755afda9968ad46a6381cd384966be4ad",
        "1fe776e62a2293f44ab514d122af6d61952bb4f127536ac29ebdc14030c9a2e4412b1154c8f2d6c4fa5629cf5736484e",
        "5608c15209a2ea5634ce8251aa7b6b4679b82adbb56f16c20db62ed15ef739414ba4e757c8af7dc6d2d1c4807acad1bb",
        "376acf682e4cdb8267fa10cba432932d2eaa0bb3460c43f2d58549d24d116d1da1c2e7872c65d360505f34761e3000d0",
        "d4af6ae9074881a92adc8d505b00e275cb00b0d43e31446f7eb3dacf007db2e5662bb2a26b5d40ad7844abd2616caf1e",
        "f702e5182706c9185a79f5aab9ddf39b8d8f2d732acda767ce6192cd22be0119cc8f881130b4172bc054a9198fe6aca0",
        "4570165716e5085e23daf087a8d83172742220a7cc4c16352286a1c56520ba6a61b2c54d8dc07d7bb7df8b1fdaa0b80c",
        "534f806497eb8664b2df0b6a2bf606d3b46421a6f228d02e7780ea524cbee5b4ce28428aae8b15a8ba25c416d30cc848",
        "e4222d5548f4778d60ce0054f751927d24da48a9d3a3fabc11f41a4928f646aac11fd49e3782a3f81d121b21f1121dc9",
        "563402a94fc8f34746f6649aa054824525138e4e130774e824046600e985283bb7c5a60821e907ea26eb85c01c2a680b",
        "97fa3a54c1387310d84b05b584dd67936f1d18be373b0e11aae6e4098d7a90409bc816463d64d1de9589e6c332cc27c6",
        "7c2d2c5ee35e710b34cbdee1f856287bea93c1abe45b925ca8dfa154b8193aba21a4de4228d37f8de8ca1ed0f07958af",
        "09082136fb3140b9b3c95e9074ebf48c722a6607523674314868d06a1bd31a672e45d24624660255728519361284cc37",
        "869925905cd5783eb8673835823b01a5a30563905af7a898ec12527d656f349f90320a5fee492363316807d855507516",
        "5125ae5a779751c3eddc2b9cc75676fcbb24fc3d1fdb67fd7e8f448adb913e9b64faaaeae41b15b155bff07bea6c7e08",
        "ec8d31dafbb32a6737eaa02ff36fb283eff9a50b5a624d7935a14f7dfa7ad8a972065f851ec1ab40b76a8cb41cc39ca5",
        "8c129dff8494070abe4135932f93bd5b3720d262fbf6918f8268f96085587b8b6f775d56c7e636690dd2ebad5c4486ca",
        "4221b99baa22a82c934c82b6a05bd94534ff0601bb916a7561a8dd5e97f858d7f7961a650e708dcf25910c7464e94a7d",
        "af895dd45d55d57581bd459573539df4a002431119b4c5566f797cbc06c8f872541865f2cd76d8229bc4cad63eeda57d",
        "64ebae4cc645a62369ef906ef9af99a2bd8ed7d65dc42aeb8e6f40a1f2374bcb54bd6fb5b80d27aaabd0ef6d5b542b89",
        "105b792938da8c02eb30444e0b5a2a5f673c628d419e364d1aa92e332cc3ec437bd15931d592a039bedf4f82d2e4e764",
        "4352286cc83da60a23c7266ba4c73058298526b8a3660b6830b699f498f056a37cc29f88283d8091f143b59ac9c848f3",
        "e92e551b18b4f94c8cd25facfc427df198c70474e8674c6cc342c19c01a41a89c968260be4c421d8ca85ace22aa70ec0",
        "562d64d9d00d152128809914d35c845c75b79d857c31b77cf595b75edd2b9be4e7f38104254f62c8cf304a9a655aea74",
        "ef38fa51311edbe8d8bdf365db5fb2e6cee3b8e0d413e76b9685b1360163b9107688ea10e998b320d031bfe9781abcd9",
        "0123ec5bb237536885c01c2fa045b0ee482b147ed0da5fc5242356278603d02fc5dda88020a1cf77fcfe0ed05d853071",
        "9fff50055be641953470876c2fef10370e84cc190976998fb417c731917a6569cf98cb871a575126ec581d349ed77d6d",
        "8ef8fd394c8d14f475e35a23d11d9f83f2136ae423a1da56f1fd68a31a8b4b26f7febaa2d052abf8ca2416aa9ca6ae79",
        "a11fa14211798f237c604f023344ddf6cdfc069651161f84b305b3196b888dec81918b8daf916f00849e94c8d815d000",
        "d94da4a62ba93a9dac23d6deab376fd7083f54b682545f9f586ba13bb1abdc85f21b52b7f59512af2b10a20d2c176fa4",
        "27f68231404f3f0c0c6b87cdd7eb08c4f2f5d1d961d1216ce5abae57f1529258752268916bdc856403c8a1892a01a1fc",
        "fa6982588f0da05a0ca646cb339fddada5064990ab53df888cab4cac5ada349376fdabe5e490e1e7a27436133a00b0dd",
        "6cb4f7065775bad16634d3c0344b8c1cc63cda9f845eac4c854b66af6553933359bc121b472562268db83733f109daeb",
        "d1e9027d44a5839002d2871119a942b094b219829535ddda00640bc5c370ac0acb19c473663b52417d5d584dac3e2d60",
        "3d83567358b1e63c08fa31ef22e4640e72e49dc7763fac6e66b8e600d65fcf52b27167486dea93f35a612be9a06a0a1f",
        "9391af405b8b193ed47c63bc894b55411d745041e30e65db1242d6fb78b0b7414c7715967bcc02b55bc8fb6eb792031a",
        "301f1eb66ec65eb311c5fc6f153f56cf56f3af0c775c211d967f84ab20580f1b77b89163c591e69bf2cd62c9467175b7",
        "77fd0a8eec0f4cf3be20057fcf876e90edada18e0dc5409d520eb2dd1f23ba2773106cca089a7ed0ac4e6bbf1772c4a7",
        "0d120c8f83709c0a732283f69b16487a615b2f830612e4b2b151b245b72135204f5ab693bb8d166803f6c51b0ea0c023",
        "349de8dc68cb2710010741671094410c6fe487b61094301b81dec06026ac02cad3dbc11a436e87641c865145a84fac29",
        "42b29bbc3c328b89b0f95e89cdec2430335f81955795d086a41d0cdd1e3382425a10ca89835ccdcf271688088ecc8dc6",
        "782e103230ee0ccce4aa7daa5c8430d2f33c89092db4f4096a60fd64b4156f1c00cc7ae858744e0245ca41d669caae82",
        "6aa2a2d0c85db65762c48a43882c5329a001a3865182adcb29dbe4f57d20d441983e3172573c1d5edcc7603c33113b7b",
        "41d2a038e4e79caa236bdb5cb529c4c8c39b1e0d48b5731a93cd38709eec903a916c25c8bc428c4cabcd2dbe0baad074",
        "fae66cd4e743d6276f2684d8bf7b0d40a5f701a6112b6939106ca14d5c7e194c1fc2f65315941c408f21560f20e62415",
        "101c866abdd0bc908d6c41b0f25282bdf3a0f8c1112a39bfb1685b1087b47389b1c0faa42454337b2e79107358509f33",
        "a412ea947f62c7dc2ba1562e020be24d92db2254641e6d8a26166eebb5b9b8c6ccf9b1a3269377c3dc002387b216001d",
        "ad501395b072852ac38f8ccd66822d0b49de4e141e52b26b83bd1535747a51a09b154a4cda32da3b1faa240a1acbe7a0",
        "8ace59e083b48f857699bded0167e7bedf5fbbe9299eefe76eb43540a336a47d87106f1c4c0cb52579f564db62344386",
        "aaa54ec719405563d2c10ec364c02854a2d2994942fb96249d6dd660223b795cbd8ab0c007e90813d4ae4c55f5553900",
        "3cfa05353b3b76328e866245ba557f508b391f0dac6982707f87d11c60486044879e724439d4f92a76b2e3a00e4b5941",
        "cb8ca152eb059cc40ffba6ef1a11b8741ed6ea13aa6ba390573adbe9eb99cd5391659325864abe9089388899fa8fd4e2",
        "178aebcecc1a6c281cd6ef0c0fb0d6555566cd52296cbb55c5e466b99a745bb74261f3a74287507bb085f623d34f0c55",
        "639bee991f073cb3014b8933bc5e5853092bf56a683afc12a2d67495a026142007a97e7c50bbd3af607514d45e98a5b7",
        "ba4a9bab674622d071e03359b0b625b296e5e980eee26cc53024b36d093110ae8b04cd90f4de662ceeebe20dda01c4fc",
        "a4739a1751072b80a011e3f50a3303a331af92809da4b149a9c6cf6dcf77c8f69415ede9524a54a75332df184b17bd4a",
        "b02007d51a53b2b14afb1c0bce51094151d97899e3b2b460836e7ab442a86c8a94922b71d0bf98e4eb73395da4c0fa42",
        "50335547c87049d7c7d99d893438fb22c475ad6de06c768e9148e103002903fbba88faeb2b50b3ba8006ce1582cc3d17",
        "48089433ec01082a368c8534d7901b9517b68215d9cc2f08acc14a42ce0b6e33335a053ba510b34c08323f6e230bc334",
        "92f8ab434abc11626b6b3970ebc620198087ab0326a6200982cd072176ac5d487e51061149309108d213f802f696ecf4",
        "24bb826c529e3782f0a936dc483a2894b5bf31e99e42a07cce655420b0252d24775087f95472ca3e5467150deaf61b01",
        "ad8272bf9ba891f3b35c9c2124d1d1cc6a6c6538724f601e9fda2262f19d78427193c2878e755876912456754aac0a18",
        "b506b529a85fa106dab304d5983a1cac10327139c768bdd7f7969d6e3aa4c794c82d690694af7cee89afe48096598205",
        "25f3ed5574656237fc0f747db2cc2b67e5aaf97dac4f4f99221b908ff41e7fea0ac42ee93964c530d21d0a10f0b538a4",
        "45925f47be71a41ac1a0f37b09d7a78226cc918c32d89895d8dcaac89c0f04a5f0b90cdb404ad4eaa3c4742f4170b505",
        "2095c882cc8ca1e0ca6481e615d47f215365040d70096154d213cafb1135ad32a9d9745721a0ef0841e3bff8e0934b00",
        "7e8e4fa79dc63c64d87a475003a3ec207fc6e60bb33795b78e070d4aa857588b0833476d21f945dd40989de13f440e16",
        "62a0ed64347df2b92cd7f994d517183b6a9ebe3fd8c574c0943d38f1578f614f395fc4a7ae4eb16b3eb796e4431a29cd",
        "90f7ea5cc327bb58655be03028d88737002f6106cddc3e180c53fa0e30a54b4ed277ec1744a6a94f92956c3a9f90e906",
        "1d65ef85fd6241e0a331b72339d9bfd57a25a89d2345066cd94968dbc835034a54842a31b3e4e4bdde656e584ce4cc44",
        "6242bb3815f7468169df15c67e2a0dc8e83610199139e9bd90e9a7f378a2aad3ee3689917df06474a9db9d6a708c127a",
        "780b2ad09e8c3228fa4a6c625c24e7b25d4124a4e2160aa3963d9a74b059153625e322d60e86faeb51511d4e812ed495",
        "98d5cdd08f503d7caed95a4349bbc80c1968d0e64b76f77cc6c9c520c36eaf2113f887f9a651567a60e3273301b5d88b",
        "cc750726314c2eb0ec12b43daea696f32028baa279455cfd0a65c63c6015524b09afbaa353200beddc8b9453df4536a9",
        "a0c43041876d26ddccce0cd00f87c93443d101f5751f0257c903fa0cc08e5628c13232593e99f5d4f07bfa2809ee4438",
        "c82e4f3b6480c156ea2a99a41312bad14615d46846054f28082abe9f0ebafbb1f85a6e19266441e87725559fafd20c3c",
        "0222c5e9d9f752627ec432437bd0a98ad78d7f66f52a3a95225fc80d17fefde458d9763f1ca0d8d649dc7c1c43778083",
        "e0b0aeb2e564f6613974caadf124cc2fdd77e73e40a45747528b8364053bda61c34d01cca62d55040d372dd0cfe927a6",
        "7a94992338e98e2618dd34ddad1e882c2390d881ea439c94e01db38bc0c631ef55e1bef562d7bca2f3346f4783b2b5d7",
        "88ed3877bc0676131fb100e84c3580d4cbfeb03942e2bb7d4f7f04a4fe18c88ef402a67310b233a313ebc7c29a8d6453",
        "3195f448acf2169b7b491d3b5d5659d3b96089575d7e316296fbe8aa9cd25f7c532766e1908ef1c88150978a9b34de3a",
        "f524db5d9d4bfc5d8b5a295692fe0491e840df0a006e92db24b57370291f42b73840b27c1cc00559e752d643b63a5530",
        "c35974274867af269acb5f3ea7b40024bbea6dc9b9a2ecb293b9374318ba11d56570afc3ba0b32b77b1aa452cb335d5e",
        "36c831448d215ca27befc20eca6e33d2c45b1205d8058002ec62c5037a4863863472725f611deccc2846f4b031a03385",
        "1f3474090324849966581404f3b111dd861494d553e5037b80ae89490b814842745e67c47759c9340048458720705316",
        "44ebe1d7a525db9927542fae2b67be4aa0e9a55740307165fd0dcc3c1700e9e4bce452903dec925c97b8f7fab6f306f4",
        "81fd1bbbc0fe3dc3dfcd014240c1621088499419809db93da044b002e86f0457c6470831722c4a4c63c6282b666ccbdb",
        "48fa4566a80171c3c25acb38d6f6fee3824527213ec77b740040da8885f611ac7317ba29659f12d5a17410f80429d303",
        "1a40e6154667cf83e00022b09c43b82fb3f5226abd5256afbce27966651dbab8311b5487cd58826a076b00a55f6c8552",
        "814f8522338f28b2e617d2ed6c1da218910eb6872a1ad98e20282b4fc82cdcafa0080e1c1e46de8421dc9cb68e3b6cd5",
        "bb72979dfd52b4d4a20328d6da3696d43720733e07646a8cb00c9e90ca4a68d00cb71b217adfc0466c29422db205f25b",
        "586977b862f7c3008add99a47ae85a198f2a28837b348099d628cc4e5a29b18bd2004d6c66affe9573d9bdca24e97ba0",
        "20145aa6b58e9106df18879523a8d70b25cc93b08cfd51590ca707f7e9fe81ed6b8e9d6c1fcc7afd30a7233d3e137c38",
        "4317087c91c172e392cc782e69da7cb20980f680cd8c7a7eeb6d4a0c2a2c84859093adcca0445a51cb9500b00429b145",
        "03916e063006e3b5b50c01f43e10d240b1e23decb44c642931c10068469403ca70d613900ed0ca7b1f5b29b4d2773981",
        "df147d3d78998d4b819a8e8c40bd0a19572c5d7d1d82d598c4c27bfa41651d676597ebbd5f5b40e0c9c1af0c3d810edf",
        "d835e4abcab53ab6694f4ee14b748e746ae845a76822e9213f73a8452226e30d69f5530f928496032a1d98f092c503ed",
        "4442d20371a4327a243a2c2ccc31471c04455762752fa85e29d52b1a1c9e07a45a8ea1fefa506632323243e1fab1231c",
        "00525bc8c448ecd8731a5ef6f8cdd2bf64877f8b8a2e5788221b91ed95e5b8d83789ddecdc8e27a760cd68734eca5673",
        "6e392765c9dd780213653b2d03683a1132f566752162db4940c0f420a4fa30df64816d49a7b8547f3cbf739e91e844ca",
        "c49442fe5d61dc33b16b55047498499898eb8a02b5a90959e6217bf252cdc5c790baa79efc25d73f0565e84584bacdb8",
        "466624a67d091a57a061fe4a07ad2b07b55e496dffd51e893ad61eb4cce26b28875a680b7416a9f26f41daa17f1299d9",
        "133b296344376e215068abdeafc6e2737558e20e17c91e7437695f57a861e7af8cd88ad9d0f1b5309443ea1b85de3bec",
        "1e03236a7c3694436ba10d1c50a8ac01278d0cc5461dddf6d50d992d41d07c6604b195f791b63792e5bfb68f4ef99eb0",
        "8f1278b240d536d26fe273b4869dfd3f685e29d97de2102614049c67cfc87edf27d41bdeaeaca84411964a6c61b91e31",
        "a279a314a55f362737402914d1ed450233adf7b03b6fb95de38b6ec97b5d03d16b1ae1a3359ba6682896aa827a27a80d",
        "505f800531c687ad2fa47bc1c0cca67798b9f51f3452ec99e7ccf00a289460987155c85e2df822cd057a03113a891242",
        "d149db1ed8d2ebc6012d5ffd7cf2d4a3e467693e0517e4694ef31a347235c389c8779fa20a307537f74cdd939eb5d2d7",
        "c1e84ce5f7f573cf30dd8132f94ebbd386b459fd29172a9605c096e50902e7174ea0a42b9743ec001fdda542564738b7",
        "4a70affe4d5331343daa7ba974146145dd061fb2e3aca50c6e8a51b6ccce7bd8483ec399cfcebc215477f52348174dca",
        "ec500220f50806a6235e9959920e9aef5d847de5df8d744daeac5c4598704c52199c3a5766a71a152dddb807a4932130",
        "d5b10ea3a5ec85ca1d6abefe9be2a7ef83553bdea2ac5df5c637cb5cc174de54369e186adcb91d77b591e77f08b6ee2e",
        "c877fd85f4c877a8ff60e3822b0e9b2a2e956148108cbd62aff3e71510142bb9eae8a96ed0ed73bbba6176c89891c0cd",
        "f686664c095ceb0c75177175bc0588d1b07705b912ce911f6806bad3e52cded8bd26f3a596d0190e3b6a6292ad477204",
        "74e186dd91d10f243bb11acee83effaa372c52e6f641edb30b4952990fade2ba5288dcf74aa4f2cb0edb7bdb1a5d219c",
        "d5275338f982eb8aed20d8b257648ebe86e685ec1db7ed47d7c9135c2d5f749f08dd50021df730f5eb079211b50a5692",
        "c44f48baba68e2b40b81c467d7c274ba83828bc7408e3a992b271d734b673ae450835b4697d60ade8bb4482a904e5d9b",
        "2e4f3acb7b86eb513b2b01ba5b7b7a74b699329064dba68cba982b5f20385008adb3d9a02897f83dbada818e21583ecf",
        "cd11c74ca96c77d3108e4a9f035bbaf623248ee8ba71c8309129b4bc81912e1bd834e5eab096eef4da8ff4c8df61cc1b",
        "e65753e4e1569bea9f07b11f466060f92436d0864847d55e3e6ca833051d5f837d3702b239f462206167e36db3ca7724",
        "cf40e0492bcec4100fbc76c86417e4dc121473b2cf55cd9e91efb5d51cc01e43a68efd42e0f7e93603a3a79362ecd27e",
        "04fcea3d2648be04bfe0b862dba918c76238da30bd992b0b4970df94b467d36dec090241cceb649a25302387f55f6cdd",
        "2c95f40b8e1ff0580211e674452f8f8d556325dfeccee3d7e1ca0f366e86957a186d325c9971357d60f995edf3a2a6c1",
        "af2fc570fb74dd0f566ed67f84ebed6663dd6cfe482fdd2521ade807bc2ba2b2ade782e94726f5c16907ef3e41079923",
        "fc163de966775dec376d6e06f301c0f60b8ef40bfe4a73fcc82435b687bcae8dacad9bf51f6c8c9bddadd875cd8d2ca5",
        "fc03deadd07f657b3c69deacfe60eb07fbd15536fc1572fc80f9cef9b067cc1cac57c8f9dcd2e39b67facd5afb11f7fd",
        "95e0aeb41461f99164fa99661f3fe0f8f121dd3a74f04e733fd07ca11f4dbb7ee572f1e67b84fa08ba873057d30e1be8",
        "60937cde8b031db70e37182cd18f45eb20353d1e002e0107d9c56b34d5275a59e8aa9b8e9bcafb84f500e76a2a246488",
        "541c5baa9d13ff19d3f934f9d61c58e841b80915ca91fde641c574fb8bfe8f44f89ad9d3910fd9ebc0d7b3bd9bfa8e9b",
        "e5182efd089760b06c361f3bae23001e1ca6ea6ecefcb47706fb7900582bee7df15d7a4609fd4b594d7b9dee3ef931c1",
        "ee5b852f69f40d5562e7a28be87c207af1cb071a03eff962e4fc6009912b854f4beee472a8a31f22a301372a1e0267a3",
        "7935faf289d0e39bc6303dbef569e7336475d5c71cc295b830e4e0e33bdf76a96c2e6d9afa3ca1f3ea8058bbaf55d56f",
        "23c7891ed0399708e8ec4c6244d5f8819ded6c64c7c2afcc1e983aa82587f635fee9b9805a3c983418b79336dc92edbe",
        "1092a7bbe70b6c8a0556070eddbf671e4002e8f1136b5361705719657ddf9c363017fcb09b5940d8eb6c8bb46979d804",
        "9e7304a4964045668c1094921dea3d2ceb330d4aba6f3246664013d69bcffce4eb3e42f2733d21130b9e745156508c0b",
        "abb62388ac842fac767da1df15b460b305584e91cd1f5f456beca9ca17eea7b0fa85cb8a1c546bbfc212ab5d76d142b0",
        "380608b6e74eaf81550f615dd65915ee455aba602c62824bbf0daebbf9925c7a17a0efdda59c0b6b8a207a189bacf396",
        "4579eac5a5460ced68c8a0720eeb5039c25c9b129b60ea17b6afae0e9f6db6b79a8efbf7b049911cf276ef0550d429bd",
        "18c9600afe48cda7079c58dbe4034ac9e27783edb0349319a331aa0e6d1112c18a00e75a45e30e352f64377710da1e56",
        "fefbdb0eb8b580b3de587c790d984bf93ab3c77d6e833223196f24f2a29f43b34694edea7e4693dcb935d4aea27de600",
        "c07c40bda3dfb9760474e005cc113c07e73a319536e18c0e5d604f8a806d52ed942b699cd9910c3eea82261c1614b460",
        "d215a2af8618d003b927ed7d2348fc1cceb887819704b1066660fe8dad4fa0bc0124f30a24329e157e633f2780dd9cc0",
        "a801cc37a609dd97c1748dc7cf4afa38f266a70b13bf0c6f2b1e02eaac903e43acfcf6102ba798e38c2357482c26bc02",
        "a7a4c69441911552af74ea95c3767dbdb9587b5cd1a146e85e7b9726575745bcc270f548875a0359f8c6161fbfeb0fbc",
        "3674d01d68b8fe9cce8d2d1d7a3443bb9217d90c1fe027c2730858e08a508523f911483e0fbfbebdedbf2324b9db49f7",
        "b5c9d1f5f5fd9eae54bb089c8c61d41f57dd99a670d798996ed551d3ab90945caf200413f07604753b568b4e95f71743",
        "e80a17c0bcc0303764412b6118ba68c33cb70ec25d474113a50da17337c141140b1c2a0ca92b1ab1852f53d04d1b7499",
        "d2b468b5b8c53a3bb60ef3316020d7c268acc6deead307b2536fc91c647dca70d10591efef66943bc0944a2670ef8510",
        "d891679092b9b61d64ee3b8714f35e075443285858085930a43847b860100467140ed27b100f589f4877852d76c39111",
        "732d50a427524e05c46a44a1c516896a97bf1cd41258a00eab3773de2e872d9c3ee948019fdaae166ebbb5d4e17ac160",
        "4de05c91785e8bca2ebbe4120dab2b7ead2997e25197371aa0e989d9c53884e84561c829835c3d41897e88ab88450b62",
        "5b910b025f5241c30f44266e9c0b5ad9237d24e2003ba36ac4566c8672f50897b4807c5a0b2e113ea8d8b1f4f398146d",
        "044099799996b04209b5869d9b1636cd899a3d990c14351b347850f8b06e5771292aaebd28a9aa6e998ccae3c52bed2d",
        "4552ae302547029bf387f48b8016d58ed102270d5ec6f588f27b65404e390f44f5bd42f1d5fada80a9f2cdb538909875",
        "3f0619c2813884b6ac3f504c321774d30d4378b4c9e072c388587d7f04acbebb0832ef94035b31876e83cdfc5c192e3c",
        "6e759e114b2994855e22f57d82ee6a04bb83b09a7d8763f423144a1a41f30e059a15b3965dffd9b948b625afef992537",
        "5e08b52bfb19dc8d803949c5873e120a9883520fc1faeb45d381b0c63a30c7cce437e48f1e65f09544ef2bb9b1cbc885",
        "1a72fc1dcb206ccec0bcbec2685ec8cf88ec7b516ed451b9e597daf8724e948b049bcfb13e3b0592f74037912874836f",
        "9e7bee6b84fd59fd66b95e01bda2b28be23b3bcdcfc30d507e27ce9464266bf86872162d2d20720af40837be137f78cd",
        "8c6073adc30b8589fd9ad1729366e61710f5461a66e9891f9dfc6c6877c94d3ec4fc0606463579d42e7400daf8b3872a",
        "00b9acd13d1057447a460586e161d847984d2fd108d6eabababe0b8d5a17c111346f86cbebf9b2098973345f7298dde0",
        "39cca90104e5e2304ccfad6f05b5e4544abed55c05c0f6c56be4297d0614135bddf16fb8e3408089f20dc44fe42c81c8",
        "c52fe17e219163033bdfd98fe0da892821b28c1c48aa39a81e965e5dcb00528bbab2646a9d32387fa96cd9b026c64f5f",
        "4011bfd5ab1c33594612bc627d504a66555656cd64afccae432424cb654d7d3bbcaae22c64f986a28d1eeb1b070deb6a",
        "ec6cb9bfa7cb91836cfb4948369d3f9356296ef09aeb4dca738105dfdac4ce2d0a99cdb51593062563a2b74c1e041274",
        "a3bdcce2796400e9ae676edd681533ce289baa21132a0fef5041a87a26b865a4d9f466e4d84b884c7b11fdb03d61bfea",
        "ad73c8f76fbb88f81b00993eccb6f75ea4ba58db3c52305a95fdace580eb938c5c2d553a31317db4ee462713dd5c3968",
        "3c3eccb00bd0859c6b9121e954c1b64b6c3ef4de0c74a68dfa0323b5f292affa58eb71399af25eca70c00d92fdf87251",
        "ef5023b35e64ba6fb5203a04d52b9eceb180fa7ba1592fb4ae88f9fe624e57de9de813e4da570c0e2e4c7d42f9cc266f",
        "a4e4182696d7d67946502ccaa7de98ceca311d1440929f63a1c32c5edfd70917d0b84a92568f11afca85672700859aa4",
        "fb748ed555d9b8329bd073ffb09afc4c492ba38a52acf2c98cd7d26f6757a01a804b85945c6172be48c54999c815abbc",
        "e1e3e2d3023a823094d96de0e9f343ea8aa479b2d84863edb7c9725da1f375f93065d0194f73193f683f381c897a8501",
        "3a3e6180fa15f15b7e5fa8941b5543341d1e1f0a01e031a4c4d5c028b857a3245fa45db17a4cd92e7ed9446ed6734381",
        "f67ee1e0f461dd6974abcb8b5110889ded73896c78494ef70f2e3f9637db766d9413c4f21b9415bad0cda98da4acb8ae",
        "9ee4fee5e5222eba09ad4027e5e7d2e1d62983257c96600d0ad78128930fccf54a33e88299b513376c18063d92eaa03e",
        "a9df6cc670139e4e71b0f41f10a71c865e541f866acf61f347dcbb7a66f51d02ce6c4694ebcdbc3a9bf9eeccabcceb47",
        "3dac1fad3a8326c60f7ebe3f6a0c5ff741e8b5e403eb05d35d6574cfe68f80bea37c3da72df65ad10ebe2f2547794bc7",
        "5ae09ad8c3760f2b4ed7d757383518d5b35bb74cf27972829afc3f9a931df4d2975fe5b14f444579b287ab6d071d5242",
        "4fa34718df18ca3d55ad89bdc9e9177b1939b2fb64c12bee0e592ef3b4f834bb03a1ad1966afe267d616719c0972cd9e",
        "59636cfd423d24d65fdb9d52d64265081bfd6239e6049fbc56567f84b30b95142d37b005b9f51c23a7a26c369bee6729",
        "ba63cee59596c34c092ab49f065314831e40a90154789bf4a006df67d251c5536422fc2035820b6add260e06d3160707",
        "58cd1d623572080c20462b94a343ff63508fb558c088953362e69cc584492d215232b7d7433a985594d8d4cd0d51e2c7",
        "72999841da2001130493b6b04b32eb13c610a391504a329b05c5bbb0e5c36d5938b0806d516563bc8d96fb221393c01a",
        "26bf379a17fa95f8eb10dced6da4e448ea8c04469722eca44d6e3e388736321f0f55f57a01eb090c446421c92081044c",
        "2831b966e3f285c3bcb63e3fa0e4486ce97b886ba76dc2812b2c05b5e20b3c494d0f99a6339add2535ec35da93ef9a7d",
        "454dbeca2266629fc1c57617944d0ab323a113321bb84e46eed0a9b8163d0c2b949fd868602910c6775307985f94fc08",
        "a735364338eac190ee7872d9d9335072ed4da8faee4bac99fb2eb126ef85ae1ce17c7e3110ec0661d92a7074346216de",
        "0bc1b78009d2e5016e5ad808ae983a28814bbab281e6256176292320dd5047767d62861661767d824450246072361653",
        "cbf0bc10b2747f21e71fe1624eca6b573a22ab15bfab17c36bafa22320c9f571420bb54883b9b8efd2a92d1799ae0fe9",
        "171ad3a342bbbf0ddb9f74f0e527d0b4f0aa7945c5ae2032660e15c4f67baaa1cfb38f5876d362eede86c2af57572fb1",
        "e800280a43f61c7d6a20c5753842cd0e8923ab91cda7e50bb9b1cec73b9b9392996e46ae8fcbac30943d87e572c1f6b8",
        "fc099b171b4f8d2c555f5e62cd3783b0a083095c39c0668f4a33a30beb7d89457607b6379abc36a6560e5381d8b9b43b",
        "456f3eb00ee28d123418116909f3baad16ecd100a1125f433c817438439ee5d1bbd25dda3b865b62f1ab77b562bcbda3",
        "91b027339a58a98a468f089691fc36dd6c60eb50e4b2d59f8645a1dfa95f00ea8dc691d5365f50585f5c6b0bcb8fc933",
        "45c97a2b5d60b0377507d4789ee7a1c10c844e51bd3e62758693410e7575a2ad61ec25d4164a3abb0e5e5455b034081a",
        "be46892d94e6838c7963f882f685d78908a1fef642ccc16f7f7568d8d1659dd31c500f0540b62fc1a863ed7fa0821990",
        "410523c021266e0f01c54c11b6b420ac164113daf5a079b69c14add7aa7da37615a5a29637b6d2d71ace648a4cef1bbc",
        "d3bc1d19ba02bed3274d00f0269c21d7507c7e09eb92bde2dc98d953e17a51ffe17379f97db09ff1bbacbe3f26f62a44",
        "8d48a05703d900ce6ff240b8c5f369bee082cd5376629e15550c610bd58471141be828a460b8914626c6393d6a787d1c",
        "a1ed009a7c572156713356587b6ee26b69b389b330b3f9e20e99b0e65a6bbb3b66d88d12547c0f12bfd32b5805dbb022",
        "19b5fff35ffff8dffe8f3ffffd8fef77fad3c7fc93fffef79f3fffac149cd9bfffb43c2f96e65fd5c1f105fac463fa60",
        "a79cfff5be7f3e456447e53c6e50fbdfef0778b86cf0affad7fbe7ef7ffd5d5d3ca2fff9fb5dfa09a6ff0e91ff0f83e2",
        "c07c5fa2d5d17f0b6d8efefdbe797f63445a7fd2e1f3b3e97f24dd0e34c55cee6fb0d410b093e76ef0d75765b960b9be",
        "ba7ca95ce7fb02327c3cffe9ff9a7ffe3d6660fff9f39fbfd27f00963fdf5cf17af0af8e9f2b7f4af9cb83bfbf86fc53",
        "f17bfdcfb72e4f7f6a795f47d77f66fa537ac2b07ffda92fa6f7ef3f7fad7f8f3f9f788032299c00fffe3accfe145769",
        "7d0f2da3bed68dd25761037bc2f7752ee30950ffe4e602106811746e95fff97fff1f43356692",
    )
)
TIMEOUT = 30
RATE_LIMIT = re.compile(r"^(\d{1,6})/(second|minute|hour)$")
SAFE_IP = re.compile(r"^[0-9a-fA-F:.]{2,45}$")
SAFE_NAME = re.compile(r"^[a-z_]{2,24}$")
COUNTER = re.compile(r"counter packets (\d+) bytes (\d+)")
ELEMENT = re.compile(r"([0-9]{1,3}(?:\.[0-9]{1,3}){3})(?: timeout [0-9a-z]+)?")
SERVICES = {
    "22": "ssh",
    "2222": "ssh",
    "21": "ftp",
    "23": "telnet",
    "80": "http",
    "443": "https",
    "2375": "docker",
    "3306": "mysql",
    "5432": "postgres",
    "6379": "redis",
    "11211": "memcached",
    "27017": "mongodb",
    "10085": "xray-api",
}
PORT_KEYS = ("ports", "syn_rate", "syn_burst", "conn_rate", "conn_burst", "udp_rate", "udp_burst", "icmp_rate", "icmp_burst", "ban_timeout", "set_size", "enabled", "rkn_enabled", "rkn_logging", "rkn_allow", "rkn_exceptions", "manual_bans", "unbanned")


SBIN_DIRS = ("/usr/local/sbin", "/usr/sbin", "/sbin")


def ensure_sbin_path():
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        return
    raw = str(os.environ.get("PATH", "") or "")
    parts = [item for item in raw.split(os.pathsep) if item]
    changed = False
    for folder in SBIN_DIRS:
        if folder not in parts:
            parts.append(folder)
            changed = True
    if changed:
        os.environ["PATH"] = os.pathsep.join(parts)


ensure_sbin_path()


class DDosError(Exception):
    def __init__(self, code, message, stage="ddos"):
        Exception.__init__(self, message)
        self.code = code
        self.message = message
        self.stage = stage


def emit(payload):
    payload["proto"] = 3
    payload["result"] = "ok" if payload.get("ok") else "err"
    if not payload.get("ok"):
        payload["msg"] = str(payload.get("message", "") or "")
    sys.stdout.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")


def parse_flags(tokens):
    flags = {}
    for token in tokens:
        if not token.startswith("--"):
            continue
        body = token[2:]
        if "=" in body:
            key, value = body.split("=", 1)
            flags[key.replace("-", "_")] = value
        else:
            flags[body.replace("-", "_")] = True
    return flags


def number(value, low, high, fallback):
    try:
        parsed = int(str(value).strip())
    except (TypeError, ValueError):
        return int(fallback)
    return int(max(low, min(parsed, high)))


def truth(value, fallback=True):
    text = str(value).strip().lower()
    if text in ("1", "on", "yes", "true"):
        return True
    if text in ("0", "off", "no", "false"):
        return False
    return bool(fallback)


def ports_text(raw):
    if isinstance(raw, (list, tuple, set)):
        text = ",".join(str(item) for item in raw)
    else:
        text = str(raw or "")
    out = []
    for match in re.finditer(r"(?<![\w-])(\d{1,5})(?!\w)", text):
        value = int(match.group(1))
        if 1 <= value <= 65535 and value not in out:
            out.append(value)
    return ",".join(str(item) for item in out[:16])


def path_of(flags):
    directory = str(flags.get("dir", "") or "")
    if directory:
        if not os.path.isabs(directory) or ".." in directory.split(os.sep):
            raise DDosError("bad_path", "the directory must be a simple absolute path", "arg")
        return directory
    return CONF_DIR


def conf_path(flags):
    override = str(flags.get("config", "") or "") or os.environ.get("DDOS_CONF", "")
    if override:
        if not os.path.isabs(override) or ".." in override.split(os.sep):
            raise DDosError("bad_path", "the config must be a simple absolute path", "arg")
        return override
    return os.path.join(path_of(flags), "ddos.json")


def rules_path(flags):
    return os.path.join(path_of(flags), "ddos.nft")


def rkn_path(flags):
    return os.path.join(path_of(flags), "rkn_subnets.json")


def utc_stamp():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


LOCAL_V4 = (
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
)
LOCAL_V6 = (
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("ff00::/8"),
)


def non_global_or_unsafe(net):
    if net.is_loopback or net.is_link_local or net.is_multicast or net.is_unspecified:
        return True
    if isinstance(net, ipaddress.IPv4Network):
        return any(net.overlaps(loc) for loc in LOCAL_V4)
    return any(net.overlaps(loc) for loc in LOCAL_V6)


def clean_entry(raw, allow_private=False):
    token = str(raw or "").strip()
    if not token or CONTROL_RE.search(token):
        return ""
    try:
        net = ipaddress.ip_network(token, strict=False)
    except ValueError:
        return ""
    if net.is_unspecified or net.is_multicast:
        return ""
    if not allow_private:
        if non_global_or_unsafe(net):
            return ""
        if isinstance(net, ipaddress.IPv4Network):
            if net.prefixlen < MIN_MANUAL_V4_PREFIX or any(net.overlaps(p) for p in PROTECTED_V4):
                return ""
        else:
            if net.prefixlen < MIN_MANUAL_V6_PREFIX or any(net.overlaps(p) for p in PROTECTED_V6):
                return ""
    else:
        if isinstance(net, ipaddress.IPv4Network) and net.prefixlen < MIN_MANUAL_V4_PREFIX:
            return ""
        if isinstance(net, ipaddress.IPv6Network) and net.prefixlen < MIN_MANUAL_V6_PREFIX:
            return ""
    if (isinstance(net, ipaddress.IPv4Network) and net.prefixlen == 32) or (
        isinstance(net, ipaddress.IPv6Network) and net.prefixlen == 128
    ):
        return str(net.network_address)
    return str(net)


def parse_entries(raw, allow_private=False):
    if isinstance(raw, (list, tuple)):
        items = [str(part).strip() for part in raw if str(part).strip()]
    elif isinstance(raw, str):
        items = [part.strip() for part in raw.replace(";", ",").replace("\n", ",").split(",") if part.strip()]
    else:
        items = []
    out = []
    for item in items:
        cleaned = clean_entry(item, allow_private=allow_private)
        if cleaned and cleaned not in out:
            out.append(cleaned)
            if len(out) >= MAX_CUSTOM_ENTRIES:
                break
    return out


def split_collapsed_entries(entries, allow_private=False):
    v4 = []
    v6 = []
    for item in entries:
        cleaned = clean_entry(item, allow_private=allow_private)
        if not cleaned:
            continue
        net = ipaddress.ip_network(cleaned, strict=False)
        if isinstance(net, ipaddress.IPv4Network):
            v4.append(net)
        else:
            v6.append(net)
    return (
        [str(net) for net in ipaddress.collapse_addresses(v4)],
        [str(net) for net in ipaddress.collapse_addresses(v6)],
    )


def sanitize_rkn_networks(lines):
    v4 = []
    v6 = []
    for raw_line in lines:
        token = str(raw_line or "").strip()
        if not token or CONTROL_RE.search(token):
            continue
        try:
            net = ipaddress.ip_network(token, strict=False)
        except ValueError:
            continue
        if non_global_or_unsafe(net):
            continue
        if isinstance(net, ipaddress.IPv4Network):
            if net.prefixlen < MIN_V4_PREFIX or any(net.overlaps(p) for p in PROTECTED_V4):
                continue
            v4.append(net)
        else:
            if net.prefixlen < MIN_V6_PREFIX or any(net.overlaps(p) for p in PROTECTED_V6):
                continue
            v6.append(net)
    return (
        [str(net) for net in ipaddress.collapse_addresses(v4)],
        [str(net) for net in ipaddress.collapse_addresses(v6)],
    )


def decode_rkn_zhex(blob):
    clean = str(blob or "").strip()
    if not clean or len(clean) > MAX_ZHEX_CHARS:
        return [], []
    try:
        compressed = bytes.fromhex(clean)
        decomp = zlib.decompressobj()
        raw = decomp.decompress(compressed, MAX_RKN_BYTES)
        if decomp.unconsumed_tail:
            return [], []
        parsed = json.loads(raw.decode("utf-8"))
    except (ValueError, zlib.error, UnicodeDecodeError, json.JSONDecodeError):
        return [], []
    if not isinstance(parsed, dict):
        return [], []
    rv4 = parsed.get("v4") if isinstance(parsed.get("v4"), list) else []
    rv6 = parsed.get("v6") if isinstance(parsed.get("v6"), list) else []
    return sanitize_rkn_networks([*(str(x) for x in rv4), *(str(x) for x in rv6)])


def load_rkn_subnets(flags):
    cached = read_json(rkn_path(flags))
    if cached:
        rv4 = cached.get("v4") if isinstance(cached.get("v4"), list) else []
        rv6 = cached.get("v6") if isinstance(cached.get("v6"), list) else []
        v4, v6 = sanitize_rkn_networks([*(str(x) for x in rv4), *(str(x) for x in rv6)])
        if v4 or v6:
            return v4, v6, str(cached.get("updated_at") or "cache")
    sv4, sv6 = decode_rkn_zhex(RKN_SEED_ZHEX)
    return sv4, sv6, "builtin"


def sysctl_path(flags):
    directory = path_of(flags)
    if directory == CONF_DIR:
        return SYSCTL
    return os.path.join(directory, "99-obhod-ddos.conf")


def unit_path(flags):
    directory = path_of(flags)
    if directory == CONF_DIR:
        return UNIT
    return os.path.join(directory, "obhod-ddos.service")


def read_json(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            body = json.load(handle)
    except (OSError, ValueError):
        return {}
    return body if isinstance(body, dict) else {}


def write_atomic(path, text, mode=0o644):
    directory = os.path.dirname(path) or "."
    try:
        os.makedirs(directory, exist_ok=True)
    except OSError as exc:
        raise DDosError("fs", "cannot create %s: %s" % (directory, exc.strerror), "fs")
    handle, temp = tempfile.mkstemp(prefix=".obhod-", dir=directory)
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(text)
            stream.flush()
            os.fchmod(stream.fileno(), mode)
            os.fsync(stream.fileno())
        os.replace(temp, path)
        directory_fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError as exc:
        try:
            os.unlink(temp)
        except OSError:
            pass
        raise DDosError("fs", "cannot durably write %s (replacement may have occurred): %s" % (path, exc.strerror), "fs")


def restore_file(path, previous):
    if previous is not None:
        write_atomic(path, previous)
        return
    try:
        os.unlink(path)
    except FileNotFoundError:
        return
    directory_fd = os.open(os.path.dirname(path) or ".", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def run(argv, timeout=TIMEOUT):
    try:
        firewall_mutation = argv[1:2] == ["-f"] or argv[1:3] == ["-c", "-f"] or argv[1:4] in (["delete", "table", "inet"], ["delete", "element", "inet"])
        inherited = (COMMAND_LOCK_FD,) if COMMAND_LOCK_FD is not None and firewall_mutation else ()
        proc = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False, pass_fds=inherited)
    except OSError as exc:
        return 127, "", str(exc.strerror or exc)
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    limit = MAX_RKN_BYTES * 4 if len(argv) >= 3 and argv[1:3] == ["list", "table"] else MAX_OUTPUT
    return proc.returncode, proc.stdout.decode("utf-8", "replace")[:limit], proc.stderr.decode("utf-8", "replace")[:4096]


def binary(flags, name, fallback):
    override = str(flags.get(name, "") or "")
    if not override:
        found = shutil.which(fallback)
        return found or ""
    if os.path.isabs(override):
        return override if os.path.isfile(override) and os.access(override, os.X_OK) else ""
    return shutil.which(override) or ""


def ensure_nft(flags):
    found = binary(flags, "nft", NFT)
    if found or flags.get("nft"):
        return found
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        return ""
    apt = shutil.which("apt-get")
    dnf = shutil.which("dnf")
    pacman = shutil.which("pacman")
    apk = shutil.which("apk")
    if apt:
        run([apt, "update", "-qq"], timeout=60)
        run([apt, "install", "-y", "-qq", "nftables"], timeout=120)
    elif dnf:
        run([dnf, "install", "-y", "-q", "nftables"], timeout=120)
    elif pacman:
        run([pacman, "-Sy", "--noconfirm", "nftables"], timeout=120)
    elif apk:
        run([apk, "add", "--no-cache", "nftables"], timeout=120)
    return binary(flags, "nft", NFT)


def policy_from(raw, flags):
    base = {
        "enabled": True,
        "syn_rate": 60,
        "syn_burst": 40,
        "conn_rate": 120,
        "conn_burst": 60,
        "udp_rate": 400,
        "udp_burst": 200,
        "icmp_rate": 20,
        "icmp_burst": 10,
        "ban_timeout": 3600,
        "set_size": 65536,
        "ports": "22,443",
        "rkn_enabled": True,
        "rkn_logging": True,
        "rkn_allow": [],
        "rkn_exceptions": [],
        "manual_bans": [],
        "unbanned": [],
    }
    for key in PORT_KEYS:
        if key in raw:
            base[key] = raw[key]
    for key in PORT_KEYS:
        if key in flags:
            base[key] = flags[key]
    policy = {
        "enabled": truth(base.get("enabled"), True),
        "syn_rate": number(base.get("syn_rate"), 1, 100000, 60),
        "syn_burst": number(base.get("syn_burst"), 1, 100000, 40),
        "conn_rate": number(base.get("conn_rate"), 1, 100000, 120),
        "conn_burst": number(base.get("conn_burst"), 1, 100000, 60),
        "udp_rate": number(base.get("udp_rate"), 1, 200000, 400),
        "udp_burst": number(base.get("udp_burst"), 1, 200000, 200),
        "icmp_rate": number(base.get("icmp_rate"), 1, 10000, 20),
        "icmp_burst": number(base.get("icmp_burst"), 1, 10000, 10),
        "ban_timeout": number(base.get("ban_timeout"), 60, 86400, 3600),
        "set_size": number(base.get("set_size"), 1024, 1048576, 65536),
        "ports": ports_text(base.get("ports")) or "22,443",
        "rkn_enabled": truth(base.get("rkn_enabled"), True),
        "rkn_logging": truth(base.get("rkn_logging"), True),
        "rkn_allow": parse_entries(base.get("rkn_allow"), allow_private=True),
        "rkn_exceptions": parse_rkn_exceptions(base.get("rkn_exceptions")),
        "manual_bans": parse_entries(base.get("manual_bans"), allow_private=False),
        "unbanned": parse_entries(base.get("unbanned"), allow_private=True)[:64],
    }
    return policy


def parse_rkn_exceptions(raw):
    items = raw if isinstance(raw, (list, tuple)) else str(raw or "").split(";")
    out = []
    for item in items:
        parts = str(item).strip().split()
        if len(parts) != 3:
            continue
        try:
            address = ipaddress.ip_address(parts[0])
            port = int(parts[2])
        except ValueError:
            continue
        proto = parts[1].lower()
        if address.is_unspecified or address.is_multicast or proto not in ("tcp", "udp") or not 1 <= port <= 65535:
            continue
        entry = "%s %s %d" % (address, proto, port)
        if entry not in out:
            out.append(entry)
        if len(out) >= 128:
            break
    return out


def port_set(policy):
    return "{ " + ", ".join(policy["ports"].split(",")) + " }"


def freeturn_accept_lines(flags=None):
    if flags and path_of(flags) != CONF_DIR:
        return []
    conf = "/opt/free-turn-proxy/install.conf"
    if not os.path.isfile(conf):
        return []
    port = 0
    mode = "udp"
    try:
        with open(conf, "r", encoding="utf-8") as handle:
            for raw in handle:
                line = raw.strip()
                if "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key == "LISTEN_PORT" and value.isdigit() and 1 <= int(value) <= 65535:
                    port = int(value)
                elif key in ("PROXY_MODE", "MODE") and value.lower() in ("udp", "tcp"):
                    mode = value.lower()
    except OSError:
        return []
    if not port:
        return []
    out = ["    udp dport %d accept" % port]
    if mode == "tcp":
        out.append("    tcp dport %d accept" % port)
    return out


def render_interval_set(name, family_type, elements):
    if not elements:
        return []
    out = [
        "  set %s {" % name,
        "    type %s;" % family_type,
        "    flags interval;",
        "    auto-merge;",
        "    elements = {",
    ]
    for index in range(0, len(elements), 8):
        chunk = ", ".join(elements[index : index + 8])
        suffix = "," if index + 8 < len(elements) else ""
        out.append("      %s%s" % (chunk, suffix))
    out.extend(["    }", "  }"])
    return out


def ssh_safety_entries(flags):
    found = []
    raw = str(flags.get("ssh_session", "") or os.environ.get("SSH_CONNECTION", ""))
    parts = raw.split()
    if len(parts) == 4:
        try:
            addr = str(ipaddress.ip_address(parts[0]))
            port = int(parts[3])
            if 1 <= port <= 65535:
                found.append((addr, port))
        except ValueError:
            pass
    tool = binary(flags, "ss", "ss")
    if not tool:
        raise DDosError("ssh_safety", "cannot inspect active SSH sessions: ss is unavailable; firewall was not changed", "apply")
    code, out, _ = run([tool, "-Hntp", "state", "established"], timeout=10)
    if code != 0:
        raise DDosError("ssh_safety", "cannot inspect active SSH sessions: ss failed; firewall was not changed", "apply")
    if len(out) >= MAX_OUTPUT:
        raise DDosError("ssh_safety", "SSH session listing was truncated; firewall was not changed", "apply")
    for line in out.splitlines():
        if not re.search(r'users:\(\("sshd(?:[:\-][^"\s]*)?"', line):
            continue
        fields = line.split()
        if fields and fields[0] == "ESTAB":
            fields = fields[1:]
        if len(fields) < 4:
            continue
        try:
            local_host, local_port = fields[2].rsplit(":", 1)
            remote_host, _remote_port = fields[3].rsplit(":", 1)
            addr = str(ipaddress.ip_address(remote_host.strip("[]")))
            port = int(local_port)
        except ValueError:
            continue
        if 1 <= port <= 65535 and (addr, port) not in found:
            found.append((addr, port))
    if len(found) > 32:
        raise DDosError("ssh_safety", "too many active SSH peers to protect safely; firewall was not changed", "apply")
    return found


def rules_text(policy, flags=None, ssh_safety=None):
    active_flags = flags or {}
    allow_v4, allow_v6 = split_collapsed_entries(policy.get("rkn_allow") or [], allow_private=True)
    ban_v4, ban_v6 = split_collapsed_entries(policy.get("manual_bans") or [], allow_private=False)
    rkn_v4, rkn_v6 = [], []
    if policy.get("rkn_enabled", True):
        rkn_v4, rkn_v6, _stamp = load_rkn_subnets(active_flags)

    lines = [
        "table inet %s {" % TABLE,
    ]
    lines.extend(render_interval_set("rkn_allow_v4", "ipv4_addr", allow_v4))
    lines.extend(render_interval_set("rkn_allow_v6", "ipv6_addr", allow_v6))
    lines.extend(render_interval_set("manual_ban_v4", "ipv4_addr", ban_v4))
    lines.extend(render_interval_set("manual_ban_v6", "ipv6_addr", ban_v6))
    lines.extend(render_interval_set("rkn_v4", "ipv4_addr", rkn_v4))
    lines.extend(render_interval_set("rkn_v6", "ipv6_addr", rkn_v6))
    safe4 = [(address, port) for address, port in (ssh_safety or []) if ipaddress.ip_address(address).version == 4]
    safe6 = [(address, port) for address, port in (ssh_safety or []) if ipaddress.ip_address(address).version == 6]
    for name, family_type, values in (("safe_ssh4", "ipv4_addr", safe4), ("safe_ssh6", "ipv6_addr", safe6)):
        if values:
            elements = ", ".join("%s . %d" % item for item in values)
            lines.append("  set %s { type %s . inet_service; flags timeout; timeout 30m; elements = { %s }; }" % (name, family_type, elements))
    exceptions = parse_rkn_exceptions(policy.get("rkn_exceptions"))
    if exceptions and (rkn_v4 or rkn_v6):
        lines.append("  chain rkn_check {")
        for entry in exceptions:
            address, proto, port = entry.split()
            family = "ip6" if ":" in address else "ip"
            lines.append("    %s saddr %s %s dport %s return" % (family, address, proto, port))
        for family, set_name, enabled in (("ip", "rkn_v4", rkn_v4), ("ip6", "rkn_v6", rkn_v6)):
            if enabled:
                lines.append("    ct state established,related %s saddr @%s return" % (family, set_name))
                if policy.get("rkn_logging", True):
                    lines.append('    %s saddr @%s limit rate 10/minute burst 5 packets log prefix "OBHOD-RKN-%s: " level warn' % (family, set_name, "v6" if family == "ip6" else "v4"))
                lines.append("    %s saddr @%s counter drop" % (family, set_name))
        lines.append("  }")
    for name in SETS:
        lines.append("  set %s { type ipv4_addr; flags dynamic, timeout; timeout %ds; size %d; }" % (name, policy["ban_timeout"], policy["set_size"]))
    lines.extend(
        [
            "  chain input {",
            "    type filter hook input priority -10; policy accept;",
            '    iifname "lo" accept',
            "    ip6 hoplimit 255 icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } accept",
        ]
    )
    if safe4:
        lines.append("    ip saddr . tcp dport @safe_ssh4 accept")
    if safe6:
        lines.append("    ip6 saddr . tcp dport @safe_ssh6 accept")
    lines.extend(
        [
            "    ct state invalid counter drop",
            "    tcp flags & (fin|syn|rst|ack) == 0x0 counter drop",
            "    tcp flags & (fin|syn|psh|rst|ack|urg) == (fin|syn|psh|urg) counter drop",
        ]
    )
    if allow_v4:
        lines.append("    ip saddr @rkn_allow_v4 accept")
    if allow_v6:
        lines.append("    ip6 saddr @rkn_allow_v6 accept")
    if ban_v4:
        lines.append("    ip saddr @manual_ban_v4 counter drop")
    if ban_v6:
        lines.append("    ip6 saddr @manual_ban_v6 counter drop")
    if exceptions and (rkn_v4 or rkn_v6):
        lines.append("    jump rkn_check")
    if rkn_v4 and not exceptions:
        lines.append("    ct state established,related ip saddr @rkn_v4 accept")
        if policy.get("rkn_logging", True):
            lines.append('    ip saddr @rkn_v4 limit rate 10/minute burst 5 packets log prefix "OBHOD-RKN-v4: " level warn')
        lines.append("    ip saddr @rkn_v4 counter drop")
    if rkn_v6 and not exceptions:
        lines.append("    ct state established,related ip6 saddr @rkn_v6 accept")
        if policy.get("rkn_logging", True):
            lines.append('    ip6 saddr @rkn_v6 limit rate 10/minute burst 5 packets log prefix "OBHOD-RKN-v6: " level warn')
        lines.append("    ip6 saddr @rkn_v6 counter drop")
    for name in SETS:
        lines.append("    ip saddr @%s counter drop" % name)
    lines.extend(freeturn_accept_lines(flags))
    lines.extend(
        [
            "    ct state new tcp flags & (fin|syn|rst|ack) == syn update @syn_flood { ip saddr limit rate over %d/second burst %d packets } counter accept" % (policy["syn_rate"], policy["syn_burst"]),
            "    ct state new update @conn_flood { ip saddr limit rate over %d/second burst %d packets }" % (policy["conn_rate"], policy["conn_burst"]),
            "    udp dport %s update @udp_flood { ip saddr limit rate over %d/second burst %d packets }" % (port_set(policy), policy["udp_rate"], policy["udp_burst"]),
            "    icmp type echo-request update @icmp_flood { ip saddr limit rate over %d/second burst %d packets }" % (policy["icmp_rate"], policy["icmp_burst"]),
            "    tcp dport != %s tcp flags & (fin|syn|rst|ack) == syn update @port_scan { ip saddr limit rate over 60/second burst 60 packets }" % port_set(policy),
            "    counter accept",
            "  }",
            "}",
        ]
    )
    return "\n".join(lines) + "\n"


SYSCTL_ROWS = (
    ("net.ipv4.tcp_syncookies", "1"),
    ("net.ipv4.tcp_max_syn_backlog", "8192"),
    ("net.ipv4.tcp_synack_retries", "2"),
    ("net.ipv4.tcp_syn_retries", "3"),
    ("net.ipv4.tcp_fin_timeout", "15"),
    ("net.ipv4.tcp_rfc1337", "1"),
    ("net.ipv4.tcp_mtu_probing", "1"),
    ("net.ipv4.ip_local_port_range", "10240 65000"),
    ("net.ipv4.conf.all.rp_filter", "2"),
    ("net.ipv4.conf.all.accept_source_route", "0"),
    ("net.ipv4.conf.all.accept_redirects", "0"),
    ("net.ipv4.conf.all.send_redirects", "0"),
    ("net.ipv4.icmp_echo_ignore_broadcasts", "1"),
    ("net.ipv4.icmp_ignore_bogus_error_responses", "1"),
    ("net.core.somaxconn", "4096"),
    ("net.core.netdev_max_backlog", "16384"),
    ("net.core.default_qdisc", "fq"),
    ("net.ipv4.tcp_congestion_control", "bbr"),
    ("net.netfilter.nf_conntrack_max", "262144"),
)


def sysctl_text():
    return "".join("%s = %s\n" % (key, value) for key, value in SYSCTL_ROWS)


def systemd_arg(value):
    text = str(value)
    if CONTROL_RE.search(text):
        raise DDosError("bad_path", "unit argument contains control characters", "unit")
    return '"' + text.replace("%", "%%").replace("$", "$$").replace("\\", "\\\\").replace('"', '\\"') + '"'


def agent_path(flags):
    raw = str(flags.get("agent_path", "") or globals().get("__file__", ""))
    if not os.path.isabs(raw) or ".." in raw.split(os.sep) or os.path.realpath(raw) != raw:
        raise DDosError("unsafe_agent", "restore agent must be a non-symlink absolute path", "unit")
    try:
        st = os.stat(raw)
        if not os.path.isfile(raw) or st.st_uid != os.geteuid() or st.st_mode & 0o022:
            raise DDosError("unsafe_agent", "restore agent has unsafe owner or permissions", "unit")
        if os.geteuid() == 0:
            parent = os.path.dirname(raw)
            while True:
                item = os.stat(parent)
                if item.st_uid != 0 or item.st_mode & 0o022:
                    raise DDosError("unsafe_agent", "restore agent parent directory is not root-controlled", "unit")
                if parent == "/":
                    break
                parent = os.path.dirname(parent)
    except OSError as exc:
        raise DDosError("unsafe_agent", "cannot inspect restore agent: " + str(exc)[:100], "unit")
    return raw


def unit_text(flags):
    agent = agent_path(flags)
    python = os.path.realpath(sys.executable)
    if os.geteuid() == 0:
        agent_path({"agent_path": python})
    nft = binary(flags, "nft", NFT) or NFT
    args = [python, agent, "restore", "--dir=" + path_of(flags), "--config=" + conf_path(flags), "--nft=" + nft]
    return (
        "[Unit]\n"
        "Description=obhod anti flood rules\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        "RemainAfterExit=yes\n"
        "ExecStart=%s\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n" % " ".join(systemd_arg(arg) for arg in args)
    )


def rule_label(line):
    text = line.lower()
    if "@rkn_allow_" in text:
        return ""
    if "@rkn_v4" in text or "@rkn_v6" in text:
        return "rkn_drop" if "drop" in text else ""
    if "@manual_ban_" in text:
        return "manual_drop" if "drop" in text else ""
    for name in SETS:
        if "update @" + name in text:
            return "syn_new" if name == "syn_flood" else ("conn_new" if name == "conn_flood" else ("udp_new" if name == "udp_flood" else ("icmp_new" if name == "icmp_flood" else "scan_new")))
    for name in SETS:
        if "ip saddr @" + name in text:
            return name.replace("_flood", "_drop").replace("port_scan", "scan_drop")
    if "0x0" in text:
        return "null"
    if "(fin|syn|psh|urg)" in text:
        return "xmas"
    if "ct state invalid" in text:
        return "invalid"
    if "update @syn_flood" in text:
        return "syn_new"
    if "update @conn_flood" in text:
        return "conn_new"
    if "update @udp_flood" in text:
        return "udp_new"
    if "update @icmp_flood" in text:
        return "icmp_new"
    if "update @port_scan" in text:
        return "scan_new"
    if "accept" in text:
        return "accepted"
    return ""


def counters_of(body):
    values = {}
    for line in str(body or "").splitlines():
        match = COUNTER.search(line)
        if not match:
            continue
        label = rule_label(line)
        if not label:
            continue
        try:
            values[label] = values.get(label, 0) + int(match.group(1))
        except ValueError:
            continue
    return values


def set_elements(body, name):
    text = str(body or "")
    start = text.find("set " + name + " {")
    if start < 0:
        return []
    end = text.find("\n  }", start)
    chunk = text[start:end if end > 0 else start + 4096]
    found = []
    for match in ELEMENT.finditer(chunk):
        candidate = match.group(1)
        try:
            address = str(ipaddress.IPv4Address(candidate))
        except ValueError:
            continue
        if address not in found:
            found.append(address)
    return found[:64]


def table_text(flags):
    tool = binary(flags, "nft", NFT)
    if not tool:
        return "", "nft is not installed"
    code, out, err = run([tool, "list", "table", "inet", TABLE])
    if code != 0:
        return "", (err or "table is not loaded").strip()[:120]
    return out, ""


def table_inspection(flags, body):
    if body:
        return "present"
    tool = binary(flags, "nft", NFT)
    if not tool:
        return "unknown"
    code, out, _err = run([tool, "list", "tables"], timeout=5)
    rows = [line.strip() for line in out.splitlines() if line.strip()]
    if code != 0 or len(out) >= MAX_OUTPUT or not all(re.fullmatch(r"table\s+(?:ip|ip6|inet|arp|bridge|netdev)\s+\S+", line) for line in rows):
        return "unknown"
    return "unknown" if "table inet " + TABLE in rows else "absent"


def sample_pps(interval=0.5):
    def totals():
        rx = 0
        try:
            with open("/proc/net/dev", "r", encoding="utf-8") as handle:
                body = handle.read()
        except OSError:
            return 0
        for line in body.splitlines()[2:]:
            if ":" not in line:
                continue
            fields = line.split(":", 1)[1].split()
            if len(fields) < 3:
                continue
            try:
                rx += int(fields[1])
            except (TypeError, ValueError):
                continue
        return rx

    first = totals()
    time.sleep(max(0.05, min(float(interval), 2.0)))
    second = totals()
    return max(0, int((second - first) / max(0.05, float(interval))))


def read_int(path, fallback=0):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return max(0, int(handle.read().strip()))
    except (OSError, ValueError):
        return int(fallback)


def established_count():
    total = 0
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(path, "r", encoding="utf-8") as handle:
                body = handle.read()
        except OSError:
            continue
        for line in body.splitlines()[1:]:
            parts = line.split()
            if len(parts) > 3 and parts[3] == "01":
                total += 1
    return total


def kernel():
    try:
        with open("/proc/sys/kernel/osrelease", "r", encoding="utf-8") as handle:
            return handle.read().strip()[:32]
    except OSError:
        return ""


def firewall_diagnose(flags):
    result = {"backend": "nftables", "ufw": "unavailable", "firewalld": "unavailable", "nft": "unavailable", "iptables": "unavailable", "ip6tables": "unavailable", "ipset": "unavailable"}
    for name in ("nft", "iptables", "ip6tables", "ipset"):
        tool = binary(flags, name, name)
        if not tool:
            continue
        code, out, _err = run([tool, "--version"], timeout=5)
        result[name] = (out.strip().splitlines()[0][:100] if code == 0 and out.strip() else "unknown")
    tool = binary(flags, "ufw", "ufw")
    if tool:
        code, out, _err = run([tool, "status"], timeout=5)
        match = re.search(r"(?im)^status:\s*(active|inactive)\s*$", out)
        result["ufw"] = match.group(1).lower() if code == 0 and match else "unknown"
    tool = binary(flags, "firewall_cmd", "firewall-cmd")
    if tool:
        code, out, _err = run([tool, "--state"], timeout=5)
        result["firewalld"] = "active" if code == 0 and out.strip() == "running" else ("inactive" if code != 0 and out.strip() == "not running" else "unknown")
    result["conflict"] = result["ufw"] == "active" and result["firewalld"] == "active"
    result["upstream_state_present"] = os.path.isfile("/etc/rkn-guard-firewall.json")
    nft_tool = binary(flags, "nft", "nft")
    result["upstream_nft_table"] = "unavailable"
    if nft_tool:
        code, out, _err = run([nft_tool, "list", "tables"], timeout=5)
        rows = [line.strip() for line in out.splitlines() if line.strip()]
        valid = all(re.fullmatch(r"table\s+(?:ip|ip6|inet|arp|bridge|netdev)\s+\S+", line) for line in rows)
        if code != 0 or len(out) >= MAX_OUTPUT or not valid:
            result["upstream_nft_table"] = "unknown"
        else:
            result["upstream_nft_table"] = "present" if "table inet rkn_guard" in rows else "absent"
    for family in ("iptables", "ip6tables"):
        for variant in ("nft", "legacy"):
            key = "upstream_" + family + "_" + variant
            tool = binary(flags, family + "_" + variant, family + "-" + variant)
            result[key] = "unavailable"
            if not tool:
                continue
            code, out, _err = run([tool, "-w", "2", "-S"], timeout=5)
            if code != 0 or len(out) >= MAX_OUTPUT or not re.search(r"(?m)^-P INPUT\s+\S+\s*$", out):
                result[key] = "unknown"
            else:
                result[key] = "present" if re.search(r"(?m)^-N SCANNERS-BLOCK\s*$", out) else "absent"
    return result


def reconcile_candidate(flags):
    if not os.path.isfile(rules_path(flags)):
        raise DDosError("reconcile_unavailable", "saved rules are missing; inspect the installation first", "reconcile")
    try:
        with open(conf_path(flags), "r", encoding="utf-8") as handle:
            raw = handle.read(MAX_RKN_BYTES + 1)
        if len(raw) > MAX_RKN_BYTES:
            raise DDosError("bad_policy", "saved policy is too large", "reconcile")
        saved = json.loads(raw)
    except (OSError, ValueError) as exc:
        raise DDosError("bad_policy", "cannot read saved policy: " + str(exc)[:100], "reconcile")
    if not isinstance(saved, dict) or saved.get("enabled") is not True:
        raise DDosError("bad_policy", "saved policy must be explicitly enabled", "reconcile")
    policy = policy_from(saved, {})
    if json.dumps(saved, sort_keys=True, separators=(",", ":")) != json.dumps(policy, sort_keys=True, separators=(",", ":")):
        raise DDosError("bad_policy", "saved policy is incomplete or not canonical; inspect before repair", "reconcile")
    expected = rules_text(policy, flags)
    fingerprint = hashlib.sha256(raw.encode("utf-8") + b"\0" + expected.encode("utf-8")).hexdigest()
    return policy, fingerprint, expected


def reconcile_fingerprint(flags, visible_policy):
    try:
        policy, fingerprint, _expected = reconcile_candidate(flags)
        return fingerprint if policy == visible_policy else ""
    except (OSError, ValueError, DDosError):
        return ""


def reconcile(flags):
    policy, fingerprint, expected = reconcile_candidate(flags)
    supplied = str(flags.get("expected_sha", ""))
    if not re.fullmatch(r"[0-9a-f]{64}", supplied) or supplied != fingerprint:
        raise DDosError("stale_reconcile", "saved policy or generated rules changed; review and confirm again", "reconcile")
    apply_rules(flags, policy, prepared=expected)
    payload = status(flags)
    payload["notice"] = "saved policy reapplied; service state and other firewalls were not changed"
    return payload


def saved_policy_consistency(flags):
    target = rules_path(flags)
    if not os.path.isfile(target):
        return "not_installed"
    try:
        with open(conf_path(flags), "r", encoding="utf-8") as handle:
            raw = handle.read(MAX_RKN_BYTES + 1)
        if len(raw) > MAX_RKN_BYTES:
            return "unknown"
        config = json.loads(raw)
        if not isinstance(config, dict) or not isinstance(config.get("enabled"), bool):
            return "unknown"
        if not config["enabled"]:
            return "disabled"
        with open(target, "r", encoding="utf-8") as handle:
            saved = handle.read(MAX_RKN_BYTES * 4 + 1)
        if len(saved) > MAX_RKN_BYTES * 4:
            return "unknown"
        expected = rules_text(policy_from(config, {}), flags)
        return "matched" if saved == expected else "mismatch"
    except (OSError, ValueError, DDosError):
        return "unknown"


def live_rate_consistency(body, policy):
    if not body or not policy.get("enabled", True):
        return "not_checked"
    if len(body) >= MAX_RKN_BYTES * 4:
        return "unknown"
    for name, rate_key, burst_key in (("syn_flood", "syn_rate", "syn_burst"), ("conn_flood", "conn_rate", "conn_burst"), ("udp_flood", "udp_rate", "udp_burst"), ("icmp_flood", "icmp_rate", "icmp_burst")):
        matches = re.findall(r"(?m)^.*\bupdate\s+@" + name + r"\s*\{[^\n]*?\blimit\s+rate\s+over\s+(\d+)/second\s+burst\s+(\d+)\s+packets\b", body)
        if len(matches) != 1:
            return "unknown"
        if (int(matches[0][0]), int(matches[0][1])) != (policy[rate_key], policy[burst_key]):
            return "mismatch"
    return "matched"


def policy_digest(policy):
    encoded = json.dumps(policy, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def status(flags):
    policy = policy_from(read_json(conf_path(flags)), {})
    body, why = table_text(flags)
    present = bool(body)
    counters = counters_of(body) if present else {}
    rkn_v4, rkn_v6, rkn_updated = load_rkn_subnets(flags)
    rkn_on = bool(present and ("@rkn_v4" in body or "@rkn_v6" in body))
    schedule = schedule_status(flags)
    payload = {
        "installed": os.path.isfile(rules_path(flags)),
        "enabled": bool(policy.get("enabled", True)),
        "table": present,
        "table_inspection": table_inspection(flags, body),
        "policy": policy,
        "policy_sha256": policy_digest(policy),
        "counters": counters,
        "syn_flood": set_elements(body, "syn_flood") if present else [],
        "conn_flood": set_elements(body, "conn_flood") if present else [],
        "udp_flood": set_elements(body, "udp_flood") if present else [],
        "icmp_flood": set_elements(body, "icmp_flood") if present else [],
        "scan": set_elements(body, "port_scan") if present else [],
        "pps": sample_pps(0.3),
        "connections": established_count(),
        "conntrack": read_int("/proc/sys/net/netfilter/nf_conntrack_count"),
        "conntrack_max": read_int("/proc/sys/net/netfilter/nf_conntrack_max"),
        "kernel": kernel(),
        "notice": why,
        "saved_policy_consistency": saved_policy_consistency(flags),
        "live_rate_consistency": live_rate_consistency(body, policy),
        "reconcile_fingerprint": reconcile_fingerprint(flags, policy) if not os.path.lexists(wal_path(flags)) else "",
        "policy_transaction": wal_state(flags),
        "rkn_enabled": rkn_on,
        "rkn_v4_count": len(rkn_v4) if rkn_on else 0,
        "rkn_v6_count": len(rkn_v6) if rkn_on else 0,
        "rkn_updated": rkn_updated,
        "timer_active": schedule["active"],
        "timer_configured": schedule["configured"],
        "timer_mode": schedule["mode"],
    }
    if not payload["installed"] and not why:
        payload["notice"] = "rules are not written yet"
    return payload



def nft_checkpoint(flags, tool):
    code, tables, err = run([tool, "list", "tables"])
    if code != 0 or len(tables) >= MAX_OUTPUT:
        raise DDosError("snapshot_failed", "cannot inspect nft tables safely: " + (err or "listing unavailable or too large")[:120], "apply")
    present = bool(re.search(r"(?m)^\s*table\s+inet\s+" + re.escape(TABLE) + r"\s*$", tables))
    if not present:
        return ""
    code, body, err = run([tool, "list", "table", "inet", TABLE])
    if code != 0 or len(body) >= MAX_RKN_BYTES * 4 or not re.match(r"^\s*table\s+inet\s+" + re.escape(TABLE) + r"\s*\{", body):
        raise DDosError("snapshot_failed", "cannot capture complete existing nft table: " + (err or "invalid or oversized snapshot")[:120], "apply")
    return body


def restore_nft_checkpoint(flags, tool, snapshot):
    current = nft_checkpoint(flags, tool)
    if not current and not snapshot:
        return
    script = ("delete table inet %s\n" % TABLE if current else "") + snapshot
    fd, target = tempfile.mkstemp(prefix=".ddos-rollback-", suffix=".nft", dir=path_of(flags))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(script)
        code, out, err = run([tool, "-c", "-f", target])
        if code:
            raise DDosError("rollback_failed", "nft rollback validation failed: " + (err or out)[:120], "apply")
        code, out, err = run([tool, "-f", target])
        if code:
            raise DDosError("rollback_failed", "nft rollback could not be confirmed: " + (err or out)[:120], "apply")
    finally:
        try:
            os.unlink(target)
        except FileNotFoundError:
            pass


def add_ssh_safety(body, safety):
    marker = '    iifname "lo" accept\n'
    if body.count(marker) != 1:
        raise DDosError("bad_rules", "saved rules lack the expected input chain", "restore")
    sets = []
    accepts = []
    for version, family, name in ((4, "ipv4_addr", "safe_ssh4"), (6, "ipv6_addr", "safe_ssh6")):
        entries = [(address, port) for address, port in safety if ipaddress.ip_address(address).version == version]
        if entries:
            elements = ", ".join("%s . %d" % item for item in entries)
            sets.append("  set %s { type %s . inet_service; flags timeout; timeout 30m; elements = { %s }; }\n" % (name, family, elements))
            accepts.append("    %s saddr . tcp dport @%s accept\n" % ("ip" if version == 4 else "ip6", name))
    header = "table inet %s {\n" % TABLE
    body = body.replace(header, header + "".join(sets), 1)
    body = body.replace(marker, marker + "".join(accepts), 1)
    return body


def apply_rules(flags, policy, prepared=None):
    tool = ensure_nft(flags)
    target = rules_path(flags)
    body = rules_text(policy, flags) if prepared is None else prepared
    safety = ssh_safety_entries(flags) if tool else []
    if safety and prepared is not None:
        live_body = add_ssh_safety(body, safety)
    else:
        live_body = rules_text(policy, flags, safety) if safety else body
    if not tool:
        raise DDosError("no_nft", "nft is not installed; existing rules were left unchanged", "apply")
    os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
    snapshot = nft_checkpoint(flags, tool)
    descriptor, check = tempfile.mkstemp(prefix=".obhod-check-", suffix=".nft", dir=os.path.dirname(target) or ".")
    os.close(descriptor)
    transaction = ("delete table inet %s\n" % TABLE if snapshot else "") + live_body
    previous = None
    try:
        write_atomic(check, transaction)
        try:
            with open(target, "r", encoding="utf-8") as handle:
                previous = handle.read(MAX_RKN_BYTES * 4 + 1)
                if len(previous) > MAX_RKN_BYTES * 4:
                    raise DDosError("too_large", "saved rules are too large to replace safely", "apply")
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise DDosError("fs", "cannot preserve existing rules: " + str(exc)[:120], "apply") from exc
        code, out, err = run([tool, "-c", "-f", check])
        if code != 0:
            raise DDosError("bad_rules", (err or out or "nft refused the ruleset").strip()[:200], "check")
        try:
            write_atomic(target, body)
        except (OSError, DDosError) as exc:
            try:
                restore_file(target, previous)
            except (OSError, DDosError) as rollback:
                raise DDosError("rollback_failed", "rules write failed and saved rules rollback failed: " + str(rollback)[:120], "apply") from exc
            raise
        code, out, err = run([tool, "-f", check])
        if code != 0:
            rollback_error = None
            if code == 124 or code < 0:
                try:
                    restore_nft_checkpoint(flags, tool, snapshot)
                except (OSError, DDosError) as exc:
                    rollback_error = exc
            try:
                restore_file(target, previous)
            except (OSError, DDosError) as exc:
                rollback_error = rollback_error or exc
            if rollback_error:
                raise DDosError("rollback_failed", "nft apply failed and rollback could not be confirmed: " + str(rollback_error)[:120], "apply")
            raise DDosError("apply", (err or out or "nft did not load the ruleset").strip()[:200], "apply")
    finally:
        try:
            os.unlink(check)
        except OSError:
            pass
    return body



def restore_rules(flags):
    tool = binary(flags, "nft", NFT)
    if not tool:
        raise DDosError("no_nft", "nft is not available; existing table was left unchanged", "restore")
    try:
        with open(conf_path(flags), "r", encoding="utf-8") as stream:
            saved_config = stream.read(MAX_RKN_BYTES + 1)
        if len(saved_config) > MAX_RKN_BYTES:
            raise DDosError("bad_policy", "saved policy is too large", "restore")
        saved_policy = json.loads(saved_config)
        if not isinstance(saved_policy, dict) or not isinstance(saved_policy.get("enabled"), bool):
            raise DDosError("bad_policy", "saved policy does not explicitly specify enabled state", "restore")
        if not saved_policy["enabled"]:
            return {"restored": False, "reason": "disabled"}
        with open(rules_path(flags), "r", encoding="utf-8") as stream:
            body = stream.read(MAX_RKN_BYTES * 4 + 1)
    except (OSError, ValueError) as exc:
        raise DDosError("restore_failed", "cannot read saved rules or policy: " + str(exc)[:120], "restore")
    if len(body) > MAX_RKN_BYTES * 4 or not body.startswith("table inet %s {\n" % TABLE):
        raise DDosError("bad_rules", "saved rules have unexpected format or size", "restore")
    safety = ssh_safety_entries(flags)
    body = add_ssh_safety(body, safety)
    snapshot = nft_checkpoint(flags, tool)
    transaction = ("delete table inet %s\n" % TABLE if snapshot else "") + body
    fd, target = tempfile.mkstemp(prefix=".ddos-restore-", suffix=".nft", dir=path_of(flags))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(transaction)
        code, out, err = run([tool, "-c", "-f", target])
        if code != 0:
            raise DDosError("bad_rules", (err or out or "nft refused the saved rules")[:200], "restore")
        code, out, err = run([tool, "-f", target])
        if code != 0:
            if code == 124 or code < 0:
                try:
                    restore_nft_checkpoint(flags, tool, snapshot)
                except (OSError, DDosError) as exc:
                    raise DDosError("rollback_failed", "restore failed and nft rollback could not be confirmed: " + str(exc)[:120], "restore") from exc
            raise DDosError("restore_failed", (err or out or "nft did not restore the rules")[:200], "restore")
    finally:
        try:
            os.unlink(target)
        except FileNotFoundError:
            pass
    return {"restored": True, "ssh_exceptions": len(safety)}


def apply_sysctl(flags):
    tool = binary(flags, "sysctl", SYSCTL_BIN)
    target = sysctl_path(flags)
    write_atomic(target, sysctl_text())
    if not tool:
        return {"written": target, "applied": False, "note": "sysctl is not available"}
    code, out, err = run([tool, "-p", target])
    return {"written": target, "applied": code == 0, "note": (err or out).strip()[:160]}


def enable_unit(flags, prepared=None):
    tool = binary(flags, "systemctl", SYSTEMCTL)
    target = unit_path(flags)
    write_atomic(target, prepared if prepared is not None else unit_text(flags))
    if not tool:
        return {"written": target, "enabled": False, "note": "systemd is not available"}
    code, out, err = run([tool, "daemon-reload"])
    if code != 0:
        return {"written": target, "enabled": False, "note": (err or out or "daemon-reload failed").strip()[:160]}
    code, out, err = run([tool, "enable", os.path.basename(target)])
    return {"written": target, "enabled": code == 0, "note": (err or out).strip()[:160]}


def disable_unit(flags):
    target = unit_path(flags)
    if not os.path.isfile(target):
        return {"written": target, "enabled": False, "note": "unit absent"}
    tool = binary(flags, "systemctl", SYSTEMCTL)
    if not tool:
        raise DDosError("unit_failed", "cannot disable persistence: systemd is unavailable", "unit")
    code, out, err = run([tool, "disable", os.path.basename(target)])
    if code != 0:
        raise DDosError("unit_failed", "cannot disable persistence: " + (err or out or "systemctl failed").strip()[:140], "unit")
    return {"written": target, "enabled": False, "note": (err or out).strip()[:160]}


def unit_checkpoint(flags):
    target = unit_path(flags)
    tool = binary(flags, "systemctl", SYSTEMCTL)
    if not tool:
        raise DDosError("unit_failed", "systemd is unavailable; firewall not changed", "unit")
    previous = None
    previous_mode = 0o644
    try:
        previous_mode = os.stat(target).st_mode & 0o777
        with open(target, "r", encoding="utf-8") as handle:
            previous = handle.read(MAX_OUTPUT + 1)
        if len(previous) > MAX_OUTPUT:
            raise DDosError("too_large", "saved systemd unit is too large", "unit")
    except FileNotFoundError:
        pass
    state = "absent"
    if previous is not None:
        code, out, err = run([tool, "is-enabled", os.path.basename(target)])
        value = out.strip().lower()
        if value in ("enabled", "enabled-runtime") or (code == 0 and not value):
            state = value or "enabled"
        elif value in ("disabled", "not-found"):
            state = "disabled"
        else:
            raise DDosError("unit_failed", "cannot safely preserve unit state: " + (value or err or "unknown")[:120], "unit")
    return {"tool": tool, "target": target, "body": previous, "mode": previous_mode, "state": state}


def restore_unit(checkpoint):
    tool = checkpoint["tool"]
    target = checkpoint["target"]
    state = checkpoint["state"]
    errors = []
    code, out, err = run([tool, "disable", os.path.basename(target)])
    if code != 0:
        errors.append((err or out or "disable failed")[:120])
    try:
        if checkpoint["body"] is None:
            try:
                os.unlink(target)
            except FileNotFoundError:
                pass
        else:
            write_atomic(target, checkpoint["body"], checkpoint["mode"])
    except (OSError, DDosError) as exc:
        errors.append(str(exc)[:120])
    code, out, err = run([tool, "daemon-reload"])
    if code != 0:
        errors.append((err or out or "daemon-reload failed")[:120])
    if state in ("enabled", "enabled-runtime"):
        command = [tool, "enable"]
        if state == "enabled-runtime":
            command.append("--runtime")
        code, out, err = run([*command, os.path.basename(target)])
        if code != 0:
            errors.append((err or out or "enable failed")[:120])
    if errors:
        raise DDosError("rollback_failed", "could not restore unit: " + "; ".join(errors)[:150], "unit")


def install(flags):
    policy = policy_from(read_json(conf_path(flags)), flags)
    if policy.get("enabled"):
        if not ensure_nft(flags):
            raise DDosError("no_nft", "nft is not installed; existing rules were left unchanged", "apply")
        prepared_unit = unit_text(flags)
        checkpoint = unit_checkpoint(flags)
        try:
            unit_result = enable_unit(flags, prepared_unit)
            if not unit_result.get("enabled"):
                raise DDosError("unit_failed", "persistence could not be enabled; firewall not changed: " + str(unit_result.get("note") or "systemd unavailable"), "unit")
            commit_policy_change(flags, policy, force=True)
        except Exception as exc:
            try:
                restore_unit(checkpoint)
            except (OSError, DDosError) as rollback:
                raise DDosError("rollback_failed", "installation failed and unit rollback failed: " + str(rollback)[:120], "unit") from exc
            raise
    else:
        target = conf_path(flags)
        previous = None
        try:
            with open(target, "r", encoding="utf-8") as handle:
                previous = handle.read(MAX_RKN_BYTES + 1)
            if len(previous) > MAX_RKN_BYTES:
                raise DDosError("too_large", "saved policy is too large to replace safely", "policy")
        except FileNotFoundError:
            pass
        checkpoint = unit_checkpoint(flags) if os.path.isfile(unit_path(flags)) else None
        unit_attempted = False
        try:
            write_atomic(target, json.dumps(policy, ensure_ascii=False, sort_keys=True, indent=2) + "\n")
            unit_attempted = True
            unit_result = disable_unit(flags)
            disable(flags)
        except Exception as exc:
            errors = []
            try:
                restore_file(target, previous)
            except (OSError, DDosError) as rollback:
                errors.append(str(rollback)[:100])
            if checkpoint is not None and unit_attempted:
                try:
                    restore_unit(checkpoint)
                except (OSError, DDosError) as rollback:
                    errors.append(str(rollback)[:100])
            if errors:
                raise DDosError("rollback_failed", "disable failed and rollback failed: " + "; ".join(errors)[:140], "unit") from exc
            raise
    try:
        sysctl_result = apply_sysctl(flags)
    except (OSError, DDosError) as exc:
        sysctl_result = {"applied": False, "note": str(exc)[:160]}
    payload = status(flags)
    payload["sysctl"] = sysctl_result
    payload["unit"] = unit_result
    payload["notice"] = "the ruleset is loaded" if payload["table"] else payload["notice"]
    return payload


def update_rkn_sets(flags, policy, v4, v6):
    tool = binary(flags, "nft", NFT)
    if not tool or not policy.get("rkn_enabled", True):
        return False
    body = nft_checkpoint(flags, tool)
    if not body:
        return False
    expected = {"rkn_v4": v4, "rkn_v6": v6}
    for name, values in expected.items():
        exists = bool(re.search(r"\bset\s+" + name + r"\s*\{", body))
        if exists != bool(values):
            return False
    commands = []
    for name, values in expected.items():
        if values:
            commands.append("flush set inet %s %s" % (TABLE, name))
            commands.append("add element inet %s %s { %s }" % (TABLE, name, ", ".join(values)))
    if not commands:
        return False
    target = rules_path(flags)
    try:
        with open(target, "r", encoding="utf-8") as handle:
            previous = handle.read(MAX_RKN_BYTES * 4 + 1)
            if len(previous) > MAX_RKN_BYTES * 4:
                raise DDosError("too_large", "saved rules are too large to update safely", "apply")
    except OSError:
        return False
    fd, transaction = tempfile.mkstemp(prefix=".rkn-update-", suffix=".nft", dir=path_of(flags))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write("\n".join(commands) + "\n")
        code, out, err = run([tool, "-c", "-f", transaction])
        if code != 0:
            raise DDosError("bad_rules", (err or out or "invalid update").strip()[:200], "check")
        try:
            write_atomic(target, rules_text(policy, flags))
        except (OSError, DDosError) as exc:
            try:
                write_atomic(target, previous)
            except (OSError, DDosError) as rollback:
                raise DDosError("rollback_failed", "set rules write failed and rollback failed: " + str(rollback)[:120], "apply") from exc
            raise
        code, out, err = run([tool, "-f", transaction])
        if code != 0:
            rollback_error = None
            if code == 124 or code < 0:
                try:
                    restore_nft_checkpoint(flags, tool, body)
                except (OSError, DDosError) as exc:
                    rollback_error = exc
            try:
                write_atomic(target, previous)
            except (OSError, DDosError) as exc:
                rollback_error = rollback_error or exc
            if rollback_error:
                raise DDosError("rollback_failed", "set update failed and rollback could not be confirmed: " + str(rollback_error)[:120], "apply")
            raise DDosError("apply", (err or out or "cannot update sets").strip()[:200], "apply")
    finally:
        try:
            os.unlink(transaction)
        except OSError:
            pass
    return True


def rkn_sync(flags):
    expected = str(flags.get("expected_policy_sha", "") or "")
    if expected and (not re.fullmatch(r"[0-9a-f]{64}", expected) or expected != policy_digest(policy_from(read_json(conf_path(flags)), {}))):
        raise DDosError("stale_policy", "firewall policy changed during source update; retry", "rkn-sync")
    blob = str(flags.get("rkn_zhex", "") or "")
    if blob == "-":
        blob = sys.stdin.read(MAX_ZHEX_CHARS + 16)
    v4, v6 = decode_rkn_zhex(blob)
    if not v4 and not v6:
        raise DDosError("bad_rkn_bundle", "the rkn subnet bundle is empty or invalid", "rkn-sync")
    if truth(flags.get("preserve_existing", "0"), False):
        old_v4, old_v6, _ = load_rkn_subnets(flags)
        v4, v6 = sanitize_rkn_networks([*old_v4, *old_v6, *v4, *v6])
    stamp = utc_stamp()
    cache_file = rkn_path(flags)
    old_cache = None
    try:
        with open(cache_file, "r", encoding="utf-8") as handle:
            old_cache = handle.read(MAX_RKN_BYTES * 2 + 1)
            if len(old_cache) > MAX_RKN_BYTES * 2:
                raise DDosError("too_large", "saved network cache is too large", "rkn-sync")
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise DDosError("fs", "cannot preserve network cache: " + str(exc)[:120], "rkn-sync") from exc
    try:
        write_atomic(cache_file, json.dumps({"v4": v4, "v6": v6, "updated_at": stamp}, ensure_ascii=True, separators=(",", ":")) + "\n")
        policy = policy_from(read_json(conf_path(flags)), {})
        if os.path.isfile(rules_path(flags)) and policy.get("enabled", True):
            if not update_rkn_sets(flags, policy, v4, v6):
                apply_rules(flags, policy)
    except Exception as exc:
        try:
            restore_file(cache_file, old_cache)
        except (OSError, DDosError) as rollback:
            raise DDosError("rollback_failed", "network update failed and cache rollback failed: " + str(rollback)[:120], "rkn-sync") from exc
        raise
    payload = status(flags)
    payload["notice"] = "rkn lists synced"
    return payload


def wal_path(flags):
    return os.path.join(path_of(flags), ".policy-transaction.json")


def wal_write(flags, policy, body):
    target = wal_path(flags)
    if os.path.lexists(target):
        raise DDosError("pending_policy", "an earlier policy transaction needs recovery", "policy")
    payload = {"version": 1, "phase": "automatic", "config": conf_path(flags), "policy": policy, "rules": body}
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    envelope = {"payload": payload, "sha256": hashlib.sha256(raw.encode("utf-8")).hexdigest()}
    write_atomic(target, json.dumps(envelope, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n", 0o600)


def wal_read(flags):
    path = wal_path(flags)
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(fd, "r", encoding="utf-8") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise ValueError("unsafe transaction owner, mode or file type")
            raw = stream.read(MAX_RKN_BYTES * 8 + 1)
        if len(raw) > MAX_RKN_BYTES * 8:
            raise ValueError("transaction journal too large")
        envelope = json.loads(raw)
        if not isinstance(envelope, dict) or set(envelope) != {"payload", "sha256"}:
            raise ValueError("invalid envelope")
        payload = envelope["payload"]
        if not isinstance(payload, dict) or set(payload) != {"version", "phase", "config", "policy", "rules"}:
            raise ValueError("invalid transaction")
        serialized = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        if not isinstance(envelope["sha256"], str) or envelope["sha256"] != hashlib.sha256(serialized.encode("utf-8")).hexdigest():
            raise ValueError("transaction checksum mismatch")
        policy, body = payload["policy"], payload["rules"]
        if payload["version"] != 1 or payload["phase"] not in ("automatic", "manual") or payload["config"] != conf_path(flags) or not isinstance(policy, dict) or policy.get("enabled") is not True:
            raise ValueError("invalid transaction target")
        if json.dumps(policy, sort_keys=True, separators=(",", ":")) != json.dumps(policy_from(policy, {}), sort_keys=True, separators=(",", ":")):
            raise ValueError("invalid transaction policy")
        if not isinstance(body, str) or len(body) > MAX_RKN_BYTES * 4 or not body.startswith("table inet %s {\n" % TABLE):
            raise ValueError("invalid transaction rules")
        return policy, body, payload["phase"], envelope["sha256"]
    except (OSError, ValueError, TypeError, DDosError) as exc:
        raise DDosError("bad_transaction", "cannot safely read policy transaction: " + str(exc)[:120], "recovery") from exc


def wal_mark_manual(flags):
    policy, body, _phase, _digest = wal_read(flags)
    payload = {"version": 1, "phase": "manual", "config": conf_path(flags), "policy": policy, "rules": body}
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    envelope = {"payload": payload, "sha256": hashlib.sha256(raw.encode("utf-8")).hexdigest()}
    write_atomic(wal_path(flags), json.dumps(envelope, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n", 0o600)


def wal_state(flags):
    if not os.path.lexists(wal_path(flags)):
        return {"state": "none"}
    try:
        policy, _body, phase, digest = wal_read(flags)
        return {"state": phase, "sha256": digest, "policy": policy}
    except DDosError:
        return {"state": "invalid"}


def wal_remove(flags):
    try:
        os.unlink(wal_path(flags))
        descriptor = os.open(path_of(flags), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise DDosError("recovery_ambiguous", "cannot durably remove policy transaction: " + str(exc)[:120], "recovery") from exc


def recover_policy(flags, automatic=False):
    policy, body, phase, digest = wal_read(flags)
    if automatic and phase != "automatic":
        raise DDosError("pending_manual", "policy recovery requires operator review", "recovery")
    if not automatic and str(flags.get("expected_sha", "")) != digest:
        raise DDosError("stale_recovery", "policy transaction changed; review it again", "recovery")
    write_atomic(conf_path(flags), json.dumps(policy, ensure_ascii=False, sort_keys=True, indent=2) + "\n")
    apply_rules(flags, policy, prepared=body)
    wal_remove(flags)
    return {"restored": True, "policy_recovered": True}


def commit_policy_change(flags, policy, force=False):
    target = conf_path(flags)
    previous = None
    try:
        with open(target, "r", encoding="utf-8") as handle:
            previous = handle.read(MAX_RKN_BYTES + 1)
        if len(previous) > MAX_RKN_BYTES:
            raise DDosError("too_large", "saved policy is too large to replace safely", "policy")
    except FileNotFoundError:
        pass
    apply = (force or os.path.isfile(rules_path(flags))) and policy.get("enabled", True)
    if os.path.lexists(wal_path(flags)):
        raise DDosError("pending_policy", "an earlier policy transaction needs recovery", "policy")
    prepared = rules_text(policy, flags) if apply else None
    if apply:
        if len(prepared.encode("utf-8")) > MAX_RKN_BYTES * 4:
            raise DDosError("too_large", "generated rules are too large for safe recovery", "policy")
        try:
            wal_write(flags, policy, prepared)
        except (OSError, DDosError) as exc:
            if os.path.lexists(wal_path(flags)):
                try:
                    wal_mark_manual(flags)
                except (OSError, DDosError) as mark:
                    raise DDosError("rollback_failed", "transaction preparation failed and manual marker is uncertain: " + str(mark)[:120], "policy") from exc
            raise
    try:
        write_atomic(target, json.dumps(policy, ensure_ascii=False, sort_keys=True, indent=2) + "\n")
        if apply:
            apply_rules(flags, policy, prepared=prepared)
    except Exception as exc:
        rollback_error = None
        try:
            restore_file(target, previous)
        except (OSError, DDosError) as rollback:
            rollback_error = rollback
        uncertain = rollback_error is not None or getattr(exc, "code", "") == "rollback_failed"
        if apply:
            try:
                wal_mark_manual(flags) if uncertain else wal_remove(flags)
            except (OSError, DDosError) as rollback:
                rollback_error = rollback_error or rollback
        if rollback_error:
            raise DDosError("rollback_failed", "rules were not applied; policy rollback failed or transaction state is uncertain: " + str(rollback_error)[:100], "policy") from exc
        raise
    if apply:
        wal_remove(flags)


def unban_cmd(flags):
    raw_ip = str(flags.get("ip", "") or "")
    cleaned = clean_entry(raw_ip, allow_private=True)
    if not cleaned:
        raise DDosError("bad_ip", "invalid IP or CIDR", "unban")
    policy = policy_from(read_json(conf_path(flags)), {})
    policy["manual_bans"] = [item for item in (policy.get("manual_bans") or []) if item != cleaned]
    allows = list(policy.get("rkn_allow") or [])
    if cleaned not in allows:
        if len(allows) >= MAX_CUSTOM_ENTRIES:
            raise DDosError("limit_reached", "allow list is full", "unban")
        allows.append(cleaned)
    policy["rkn_allow"] = allows
    unbanned = [cleaned, *[item for item in (policy.get("unbanned") or []) if item != cleaned]][:64]
    policy["unbanned"] = unbanned
    commit_policy_change(flags, policy)
    tool = binary(flags, "nft", NFT)
    if tool:
        try:
            addr = ipaddress.IPv4Address(cleaned)
            for set_name in SETS:
                run([tool, "delete", "element", "inet", TABLE, set_name, "{ " + str(addr) + " }"], timeout=5)
        except ValueError:
            pass
    return status(flags)


def reban_cmd(flags):
    raw_ip = str(flags.get("ip", "") or "")
    cleaned = clean_entry(raw_ip, allow_private=False)
    if not cleaned:
        raise DDosError("bad_ip", "invalid IP or CIDR", "reban")
    policy = policy_from(read_json(conf_path(flags)), {})
    policy["rkn_allow"] = [item for item in (policy.get("rkn_allow") or []) if item != cleaned]
    policy["unbanned"] = [item for item in (policy.get("unbanned") or []) if item != cleaned]
    bans = list(policy.get("manual_bans") or [])
    if cleaned not in bans:
        if len(bans) >= MAX_CUSTOM_ENTRIES:
            raise DDosError("limit_reached", "entry list is full", "reban")
        bans.append(cleaned)
    policy["manual_bans"] = bans
    commit_policy_change(flags, policy)
    return status(flags)


def mutate_list_cmd(flags, field_name, add_mode, allow_private, stage_name):
    raw_ip = str(flags.get("ip", "") or "")
    cleaned = clean_entry(raw_ip, allow_private=allow_private)
    if not cleaned:
        raise DDosError("bad_ip", "invalid IP or CIDR", stage_name)
    policy = policy_from(read_json(conf_path(flags)), {})
    items = list(policy.get(field_name) or [])
    if add_mode:
        if cleaned not in items:
            if len(items) >= MAX_CUSTOM_ENTRIES:
                raise DDosError("limit_reached", "entry list is full", stage_name)
            items.append(cleaned)
    else:
        items = [item for item in items if item != cleaned]
    policy[field_name] = items
    commit_policy_change(flags, policy)
    return status(flags)


def disable(flags):
    tool = binary(flags, "nft", NFT)
    if not tool:
        raise DDosError("no_nft", "cannot confirm removal: nft is unavailable", "disable")
    code, out, err = run([tool, "delete", "table", "inet", TABLE])
    if code != 0:
        list_code, tables, list_err = run([tool, "list", "tables"])
        present = bool(re.search(r"(?m)^\s*table\s+inet\s+" + re.escape(TABLE) + r"\s*$", tables))
        if list_code != 0 or present:
            raise DDosError("disable_failed", (err or list_err or out or "cannot confirm table removal")[:200], "disable")
    return {"disabled": True}


def remove(flags):
    disable(flags)
    policy = policy_from(read_json(conf_path(flags)), {})
    policy["enabled"] = False
    write_atomic(conf_path(flags), json.dumps(policy, ensure_ascii=False, sort_keys=True, indent=2) + "\n")
    tool = binary(flags, "systemctl", SYSTEMCTL)
    if tool:
        run([tool, "disable", "--now", os.path.basename(unit_path(flags))])
        run([tool, "daemon-reload"])
    for path in (rules_path(flags), rkn_path(flags), unit_path(flags)):
        try:
            os.unlink(path)
        except OSError:
            pass
    payload = status(flags)
    payload["notice"] = "the ruleset and the unit are gone"
    return payload


def proc_owners():
    owners = {}
    base = "/proc"
    try:
        pids = [name for name in os.listdir(base) if name.isdigit()][:2048]
    except OSError:
        return owners
    for pid in pids:
        try:
            with open(os.path.join(base, pid, "comm"), "r", encoding="utf-8") as handle:
                name = handle.read().strip()[:40].lower().replace(" ", "-")
        except OSError:
            continue
        try:
            fds = os.listdir(os.path.join(base, pid, "fd"))
        except OSError:
            continue
        for fd in fds[:256]:
            try:
                link = os.readlink(os.path.join(base, pid, "fd", fd))
            except OSError:
                continue
            if link.startswith("socket:["):
                try:
                    owners[int(link[8:-1])] = name
                except ValueError:
                    continue
    return owners


def listening_from_proc():
    owners = proc_owners()
    rows = []
    for path, family in (("/proc/net/tcp", 4), ("/proc/net/tcp6", 6)):
        try:
            with open(path, "r", encoding="utf-8") as handle:
                body = handle.read()
        except OSError:
            continue
        for line in body.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 10 or parts[3] != "0A":
                continue
            local = parts[1].split(":")
            if len(local) != 2:
                continue
            try:
                port = int(local[1], 16)
                raw = bytes.fromhex(local[0])[::-1]
            except ValueError:
                continue
            try:
                address = str(ipaddress.ip_address(raw))
            except ValueError:
                continue
            try:
                owner = owners.get(int(parts[9]), "")
            except ValueError:
                owner = ""
            rows.append({"port": port, "proto": "tcp", "process": owner, "address": address})
    return rows


def ss_rows(flags):
    tool = binary(flags, "ss", "ss")
    if not tool:
        return []
    code, out, _err = run([tool, "-Hltn"])
    if code != 0:
        return []
    rows = []
    for line in out.splitlines():
        fields = line.split()
        if len(fields) < 4:
            continue
        local = fields[3]
        address, _, port = local.rpartition(":")
        if not port.isdigit():
            continue
        process = ""
        if len(fields) > 5:
            process = fields[5].split(":")[0].strip('"').lower()
        rows.append({"port": int(port), "proto": "tcp", "process": process, "address": address.strip("[]")})
    return rows


def probe(flags):
    rows = ss_rows(flags)
    source = "ss"
    if not rows:
        rows = listening_from_proc()
        source = "proc"
    cleaned = []
    for row in rows[:512]:
        port = row.get("port", 0)
        if not isinstance(port, int) or not 1 <= port <= 65535:
            continue
        address = str(row.get("address", "") or "")[:45]
        if address and not SAFE_IP.match(address):
            address = ""
        name = str(row.get("process", "") or "")[:40]
        if name and not re.match(r"^[a-z0-9_.+-]{1,40}$", name):
            name = ""
        cleaned.append({"port": port, "proto": "tcp", "process": name, "address": address})
    return {"rows": cleaned, "count": len(cleaned), "source": source}


def sysinfo(flags):
    return {
        "kernel": kernel(),
        "nft": bool(binary(flags, "nft", NFT)),
        "sysctl": bool(binary(flags, "sysctl", SYSCTL_BIN)),
        "systemd": bool(binary(flags, "systemctl", SYSTEMCTL)),
        "conf": conf_path(flags),
        "rules": rules_path(flags),
        "conntrack": read_int("/proc/sys/net/netfilter/nf_conntrack_count"),
        "conntrack_max": read_int("/proc/sys/net/netfilter/nf_conntrack_max"),
    }


def render(flags):
    policy = policy_from(read_json(conf_path(flags)), flags)
    return {"rules": rules_text(policy, flags), "sysctl": sysctl_text(), "policy": policy}


def schedule_paths(flags):
    directory = UNIT_DIR if path_of(flags) == CONF_DIR else path_of(flags)
    return os.path.join(directory, "obhod-rkn-update.service"), os.path.join(directory, "obhod-rkn-update.timer"), os.path.join(path_of(flags), "rkn_schedule.json")


def schedule_status(flags):
    service, timer, config = schedule_paths(flags)
    data = read_json(config)
    tool = binary(flags, "systemctl", SYSTEMCTL)
    active = bool(tool and os.path.isfile(timer) and run([tool, "is-active", os.path.basename(timer)])[0] == 0)
    return {"mode": str(data.get("mode", "off")), "value": str(data.get("value", "")), "active": active, "configured": os.path.isfile(config), "service_installed": os.path.isfile(service)}


def schedule_set(flags):
    service, timer, config = schedule_paths(flags)
    if truth(flags.get("default", "0"), False) and os.path.isfile(config):
        saved = read_json(config)
        flags = dict(flags)
        flags["mode"] = saved.get("mode", "off")
        flags["value"] = saved.get("value", "")
    tool = binary(flags, "systemctl", SYSTEMCTL)
    if not tool or not os.path.isfile(service):
        raise DDosError("no_schedule_service", "scheduler service or systemd is unavailable", "schedule")
    mode = str(flags.get("mode", "hours"))
    value = str(flags.get("value", "12")).strip()
    if mode == "hours":
        if not re.fullmatch(r"[0-9]{1,3}", value) or not 1 <= int(value) <= 168:
            raise DDosError("bad_schedule", "hours must be between 1 and 168", "schedule")
        value = str(int(value))
        timing = "OnBootSec=10min\nOnUnitActiveSec=%sh\n" % value
    elif mode == "calendar":
        values = value.split(",")
        if not 1 <= len(values) <= 24 or any(not re.fullmatch(r"(?:[01][0-9]|2[0-3]):[0-5][0-9]", part) for part in values):
            raise DDosError("bad_schedule", "use HH:MM values separated by commas", "schedule")
        value = ",".join(sorted(set(values)))
        timing = "".join("OnCalendar=*-*-* %s:00 Europe/Moscow\n" % part for part in value.split(",")) + "Persistent=true\n"
    elif mode == "off":
        value = ""
        timing = ""
    else:
        raise DDosError("bad_schedule", "unknown schedule mode", "schedule")
    state = {"mode": mode, "value": value}
    if read_json(config) == state and (mode == "off" or schedule_status(flags)["active"]):
        return schedule_status(flags)
    old_timer = None
    try:
        with open(timer, "r", encoding="utf-8") as handle:
            old_timer = handle.read(16384)
    except OSError:
        pass
    was_active = schedule_status(flags)["active"]
    if mode == "off":
        code, out, err = run([tool, "disable", "--now", os.path.basename(timer)])
        if code != 0:
            raise DDosError("schedule_failed", (err or out or "cannot disable timer")[:200], "schedule")
    else:
        text = "[Unit]\nDescription=OBHOD RKN list update\n\n[Timer]\n" + timing + "Unit=obhod-rkn-update.service\n\n[Install]\nWantedBy=timers.target\n"
        write_atomic(timer, text)
        code, out, err = run([tool, "daemon-reload"])
        if code == 0:
            code, out, err = run([tool, "enable", "--now", os.path.basename(timer)])
        if code != 0:
            if old_timer is None:
                try:
                    os.unlink(timer)
                except OSError:
                    pass
            else:
                write_atomic(timer, old_timer)
            run([tool, "daemon-reload"])
            if was_active:
                run([tool, "restart", os.path.basename(timer)])
            raise DDosError("schedule_failed", (err or out or "cannot enable timer")[:200], "schedule")
        if was_active:
            code, out, err = run([tool, "restart", os.path.basename(timer)])
            if code != 0:
                if old_timer is not None:
                    write_atomic(timer, old_timer)
                    run([tool, "daemon-reload"])
                    run([tool, "restart", os.path.basename(timer)])
                raise DDosError("schedule_failed", (err or out or "cannot restart timer")[:200], "schedule")
    write_atomic(config, json.dumps(state, sort_keys=True) + "\n", 0o600)
    return schedule_status(flags)


def stats_path(flags):
    return os.path.join(path_of(flags), "rkn_attack_stats.json")


def journal_batch(command, timeout=30, max_lines=1000, max_bytes=MAX_OUTPUT):
    lines = []
    pending = b""
    total = 0
    errors = bytearray()
    limited = False
    try:
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as exc:
        raise DDosError("stats_failed", str(exc)[:200], "stats")
    deadline = time.monotonic() + timeout
    selector = selectors.DefaultSelector()
    try:
        selector.register(proc.stdout, selectors.EVENT_READ, "out")
        selector.register(proc.stderr, selectors.EVENT_READ, "err")
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise DDosError("stats_failed", "journal read timed out; saved statistics retained", "stats")
            ready = selector.select(remaining)
            if not ready:
                raise DDosError("stats_failed", "journal read timed out; saved statistics retained", "stats")
            for key, _mask in ready:
                data = os.read(key.fileobj.fileno(), 65536)
                if not data:
                    selector.unregister(key.fileobj)
                    continue
                if key.data == "err":
                    errors.extend(data[:max(0, 4096 - len(errors))])
                    continue
                pending += data
                while b"\n" in pending:
                    line, pending = pending.split(b"\n", 1)
                    if len(lines) >= max_lines or total + len(line) + 1 > max_bytes:
                        if not lines:
                            raise DDosError("stats_failed", "journal event exceeds byte limit; saved statistics retained", "stats")
                        limited = True
                        break
                    lines.append(line.decode("utf-8", "replace"))
                    total += len(line) + 1
                if limited:
                    break
                if total + len(pending) > max_bytes:
                    if not lines:
                        raise DDosError("stats_failed", "journal event exceeds byte limit; saved statistics retained", "stats")
                    limited = True
                    break
            if limited:
                break
        if not limited and pending:
            raise DDosError("stats_failed", "incomplete journal output; saved statistics retained", "stats")
        if limited and proc.poll() is None:
            try:
                proc.terminate()
            except ProcessLookupError:
                pass
        try:
            code = proc.wait(timeout=max(0.1, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            raise DDosError("stats_failed", "journal process timed out; saved statistics retained", "stats")
        if code != 0 and not limited and not (code == 1 and not lines and not errors):
            raise DDosError("stats_failed", errors.decode("utf-8", "replace")[:200] or "journal unavailable; saved statistics retained", "stats")
        return lines, limited
    finally:
        selector.close()
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        proc.stdout.close()
        proc.stderr.close()


def collect_stats(flags):
    tool = shutil.which("journalctl")
    if not tool:
        raise DDosError("no_journal", "journalctl is not installed", "stats")
    previous = read_json(stats_path(flags))
    cursor = str(previous.get("cursor", "") or "")
    if cursor and (len(cursor) > 1024 or not re.fullmatch(r"[A-Za-z0-9;=]+", cursor)):
        raise DDosError("bad_cursor", "saved journal cursor is invalid", "stats")
    command = [tool, "-k", "--no-pager", "-o", "json", "--grep=OBHOD-RKN-v[46]:"]
    command.append("--after-cursor=" + cursor if cursor else "--since=-24 hours")
    lines, limited = journal_batch(command)
    counts = previous.get("counts") if isinstance(previous.get("counts"), dict) else {}
    safe_counts = {}
    for address, amount in counts.items():
        try:
            key = str(ipaddress.ip_address(address))
            value = int(amount)
            if 0 <= value <= 10**12:
                safe_counts[key] = value
        except (ValueError, TypeError):
            continue
    accepted = 0
    for line in lines:
        try:
            event = json.loads(line)
        except ValueError:
            raise DDosError("stats_failed", "invalid journal event; saved statistics retained", "stats")
        if not isinstance(event, dict):
            raise DDosError("stats_failed", "invalid journal event; saved statistics retained", "stats")
        item_cursor = str(event.get("__CURSOR", ""))
        if not re.fullmatch(r"[A-Za-z0-9;=]{1,1024}", item_cursor):
            raise DDosError("stats_failed", "invalid journal cursor; saved statistics retained", "stats")
        message = event.get("MESSAGE", "")
        if not isinstance(message, str) or not re.search(r"OBHOD-RKN-v[46]:", message):
            raise DDosError("stats_failed", "invalid journal message; saved statistics retained", "stats")
        match = re.search(r"\bSRC=([^\s]+)", message)
        if match:
            try:
                address = str(ipaddress.ip_address(match.group(1)))
                if address in safe_counts or len(safe_counts) < 10000:
                    safe_counts[address] = min(10**12, safe_counts.get(address, 0) + 1)
                    accepted += 1
            except ValueError:
                pass
        cursor = item_cursor
    legacy = bool(previous.get("legacy_counts")) or bool(counts and previous.get("order_version") != 2)
    state = {"cursor": cursor, "counts": safe_counts, "updated_at": utc_stamp(), "batch_limited": limited, "order_version": 2, "legacy_counts": legacy}
    write_atomic(stats_path(flags), json.dumps(state, ensure_ascii=True, separators=(",", ":")) + "\n", 0o600)
    return {"accepted": accepted, "unique": len(safe_counts), "batch_limited": state["batch_limited"]}


def reset_stats(flags):
    state = read_json(stats_path(flags))
    cursor = str(state.get("cursor", "") or "")
    if cursor and not re.fullmatch(r"[A-Za-z0-9;=]{1,1024}", cursor):
        raise DDosError("bad_cursor", "saved journal cursor is invalid; statistics not reset", "stats")
    clean = {"cursor": cursor, "counts": {}, "updated_at": utc_stamp(), "batch_limited": False, "order_version": 2, "legacy_counts": False}
    write_atomic(stats_path(flags), json.dumps(clean, ensure_ascii=True, separators=(",", ":")) + "\n", 0o600)
    return {"reset": True, "cursor_retained": bool(cursor)}


def stats_snapshot(flags):
    state = read_json(stats_path(flags))
    counts = state.get("counts") if isinstance(state.get("counts"), dict) else {}
    cleaned = []
    for address, amount in counts.items():
        try:
            ip = str(ipaddress.ip_address(address))
            count = int(amount)
            if 0 <= count <= 10**12:
                cleaned.append((ip, count))
        except (TypeError, ValueError):
            continue
    cleaned.sort(key=lambda item: (-item[1], item[0]))
    return {"text": "\n".join("%s  %d" % item for item in cleaned[:20]) or "No recorded events", "updated_at": str(state.get("updated_at", ""))[:40], "batch_limited": bool(state.get("batch_limited")), "legacy_counts": bool(state.get("legacy_counts")) or bool(counts and state.get("order_version") != 2)}


def live_log_snapshot(flags):
    tool = shutil.which("journalctl")
    if not tool:
        raise DDosError("no_journal", "journalctl is not installed", "logs")
    kind = str(flags.get("kind", ""))
    if kind not in ("v4", "v6"):
        raise DDosError("bad_arg", "invalid live log type", "logs")
    started_at = int(time.time())
    command = [tool, "-k", "--reverse", "-n", "40", "--no-pager", "-o", "json", "--grep=OBHOD-RKN-" + kind + ":"]
    code, out, err = run(command, timeout=15)
    if code != 0 and not (code == 1 and not out and not err):
        raise DDosError("logs_failed", (err or "cannot read packet journal")[:200], "logs")
    events = []
    cursor = ""
    for line in out.splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            raise DDosError("logs_failed", "invalid journal output", "logs")
        if not isinstance(event, dict) or not isinstance(event.get("MESSAGE"), str):
            raise DDosError("logs_failed", "invalid journal event", "logs")
        token = str(event.get("__CURSOR", ""))
        if not re.fullmatch(r"[A-Za-z0-9;=]{1,1024}", token):
            raise DDosError("logs_failed", "invalid journal cursor", "logs")
        if not cursor:
            cursor = token
        try:
            stamp = int(event.get("__REALTIME_TIMESTAMP", "0")) / 1000000
            date = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(stamp)) if stamp > 0 else ""
        except (ValueError, OverflowError, TypeError):
            date = ""
        message = event["MESSAGE"].replace("\n", " ")[:2000]
        events.append(((date + " ") if date else "") + message)
    return {"text": "\n".join(reversed(events))[-3000:] or "No journal entries", "cursor": cursor, "started_at": started_at}


def service_logs(flags):
    tool = shutil.which("journalctl")
    if not tool:
        raise DDosError("no_journal", "journalctl is not installed", "logs")
    kind = str(flags.get("kind", "service"))
    if kind == "top":
        try:
            collect_stats(flags)
            warning = ""
        except DDosError as exc:
            warning = exc.message
        data = stats_snapshot(flags)
        if warning:
            data["text"] = "[" + warning + "]\n" + data["text"]
        if data["batch_limited"]:
            data["text"] = "[backlog remains; collect again]\n" + data["text"]
        if data["legacy_counts"]:
            data["text"] = "[older totals may contain duplicates; reset to start fresh]\n" + data["text"]
        return data
    if kind not in ("service", "update", "v4", "v6"):
        raise DDosError("bad_arg", "invalid log type", "logs")
    if kind in ("service", "update"):
        selector = ["-u", os.path.basename(unit_path(flags)) if kind == "service" else "obhod-rkn-update.service"]
    else:
        selector = ["-k", "--grep=OBHOD-RKN-" + ("v[46]" if kind == "top" else kind) + ":"]
    code, out, err = run([tool, *selector, "--reverse", "-n", "40", "--no-pager", "-o", "short-iso"], timeout=15)
    if code != 0 and not (code == 1 and not out and not err):
        raise DDosError("logs_failed", (err or "cannot read service journal")[:200], "logs")
    text = "\n".join(reversed(out.splitlines()))
    return {"text": text[-3000:] or "No journal entries"}


def acquire_operation_lock(descriptor):
    deadline = time.monotonic() + LOCK_TIMEOUT
    while True:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except BlockingIOError:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise DDosError("busy", "firewall operation is busy; no changes were made", "lock")
            time.sleep(min(0.05, remaining))


def main(argv):
    global COMMAND_LOCK_FD
    command = argv[0] if argv else "status"
    lock = None
    try:
        flags = parse_flags(argv[1:])
        if command in ("install", "restore", "recover-policy", "reconcile", "rkn-sync", "ban-add", "ban-del", "allow-add", "allow-del", "unban", "reban", "remove", "uninstall", "disable", "schedule-set", "stats-collect", "stats-reset", "logs"):
            directory = path_of(flags)
            os.makedirs(directory, exist_ok=True)
            descriptor = os.open(os.path.join(directory, ".ddos.lock"), os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
            lock = os.fdopen(descriptor, "a+")
            acquire_operation_lock(lock.fileno())
            COMMAND_LOCK_FD = lock.fileno()
        if lock is not None and os.path.lexists(wal_path(flags)) and command not in ("restore", "recover-policy", "stats-collect", "stats-reset", "logs"):
            raise DDosError("pending_policy", "an earlier policy transaction needs recovery", "policy")
        if command == "status":
            payload = status(flags)
        elif command == "install":
            payload = install(flags)
        elif command == "restore":
            payload = recover_policy(flags, automatic=True) if os.path.lexists(wal_path(flags)) else restore_rules(flags)
        elif command == "recover-policy":
            payload = recover_policy(flags)
        elif command == "reconcile":
            payload = reconcile(flags)
        elif command == "rkn-sync":
            payload = rkn_sync(flags)
        elif command == "ban-add":
            payload = mutate_list_cmd(flags, "manual_bans", True, False, "ban-add")
        elif command == "ban-del":
            payload = mutate_list_cmd(flags, "manual_bans", False, False, "ban-del")
        elif command == "allow-add":
            payload = mutate_list_cmd(flags, "rkn_allow", True, True, "allow-add")
        elif command == "allow-del":
            payload = mutate_list_cmd(flags, "rkn_allow", False, True, "allow-del")
        elif command == "unban":
            payload = unban_cmd(flags)
        elif command == "reban":
            payload = reban_cmd(flags)
        elif command == "remove" or command == "uninstall":
            payload = remove(flags)
        elif command == "disable":
            payload = disable(flags)
        elif command == "schedule-status":
            payload = schedule_status(flags)
        elif command == "schedule-set":
            payload = schedule_set(flags)
        elif command == "stats-collect":
            payload = collect_stats(flags)
        elif command == "stats-reset":
            payload = reset_stats(flags)
        elif command == "logs":
            payload = service_logs(flags)
        elif command == "logs-live-snapshot":
            payload = live_log_snapshot(flags)
        elif command == "firewall-diagnose":
            payload = firewall_diagnose(flags)
        elif command == "probe":
            payload = probe(flags)
        elif command == "info":
            payload = sysinfo(flags)
        elif command == "render":
            payload = render(flags)
        else:
            raise DDosError("bad_command", "unknown command: " + str(command)[:40], "arg")
        emit({"ok": True, "data": payload})
        return 0
    except DDosError as exc:
        emit({"ok": False, "code": exc.code, "message": exc.message, "stage": exc.stage})
        return 2
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        emit({"ok": False, "code": "internal", "message": str(exc)[:200], "stage": command})
        return 2
    finally:
        if lock is not None:
            COMMAND_LOCK_FD = None
            lock.close()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
