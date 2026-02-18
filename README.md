# URLock

⚠️ Testing only  

- Share encrypted data via url hash
- Nothing is ever sent to server
- Password not stored anywhere
- Lightweight : 5KB JS + 1.5KB CSS  

[DEMO](https://nicopowa.github.io/urlock)  

## Data

Input -> GZIP compression -> AES encryption -> B64 encoding -> Share  

Chromium based browsers enforce a 512KB hard limit when pasting text into the address bar, URL-safe Base64 increases size by 33%, 512KB / 1.33 ≈ 393KB raw binary capacity. If compressed data size is over 393KB, output size will exceed 512KB, get truncated upon pasting, and fail to decrypt.  


## Tests

[Lorem Ipsum](https://nicopowa.github.io/urlock/#sreNHLPCZYMpIGi0ho8M6K_Jtg7KJB0DA4Y0EMeMIn6rzhcVpRtjC_vYyAEI7YB_2Gx07TfCSDQXYlikTFUUjwikG3UA7m_4WZz0EJGPR1lvrmaIhQTmXtsGh2wpmdgf4nX2EUPifyKz6W_69xC7stzTeBo6O1Q39Groh3fOgUVgAOeAFeqc2ACouTVbkhPlkC8JGe4ldWQTa62IRoTAAh_d-XgZ6Llmg55DAxnSaWg8WZ3w4cXCAyNZ9AqM-w0OzLM8XecoRvBHSIDEMgJ4lh1Tr32rjLCx2UaCsALtDecTJqWjPpKHazWyjawB_ecEi4WGezDDy6Cok5DubgBn1_X2fx3vqpVaTrWsTpTh_lyJ_rPpHDe_UDZ_Z6qXtX3s8qXWv9W5jWvBJSrDaFoJ29dJNp5xQgu9I4D6xOfz4cMe)  
password : lorem

[200KB JPG file](https://nicopowa.github.io/urlock/test.html)  
password : test

## Links

- [IETF URL Fragment](https://datatracker.ietf.org/doc/html/rfc3986#section-3.5)