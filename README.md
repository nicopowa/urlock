# URLock 

Share encrypted data via URL #hash  
  
⚠️ Testing only  

- No data is ever sent to server
- Password is not stored anywhere
- Lightweight 5KB vanilla JS + 3.5KB CSS

[DEMO](https://nicopowa.github.io/urlock)  


## Security

Encrypted payload lives in the URL fragment, anyone who has the link can attempt to brute-force it indefinitely.  

A random password is automatically generated if field is left empty (based on [nanoid](https://github.com/ai/nanoid)).


## Dataflow

Input -> GZIP compression -> AES encryption -> B64 encoding -> Share  

Chromium based browsers enforce a 512KB hard limit when pasting text into the address bar, URL-safe Base64 increases size by 33%, 512KB / 1.33 ≈ 393KB raw binary capacity. If compressed data size is over 393KB, output size will exceed 512KB, get truncated upon pasting, and fail to decrypt.  


## Tests

[Lorem Ipsum](https://nicopowa.github.io/urlock/#sreNHLPCZYMpIGi0ho8M6K_Jtg7KJB0DA4Y0EMeMIn6rzhcVpRtjC_vYyAEI7YB_2Gx07TfCSDQXYlikTFUUjwikG3UA7m_4WZz0EJGPR1lvrmaIhQTmXtsGh2wpmdgf4nX2EUPifyKz6W_69xC7stzTeBo6O1Q39Groh3fOgUVgAOeAFeqc2ACouTVbkhPlkC8JGe4ldWQTa62IRoTAAh_d-XgZ6Llmg55DAxnSaWg8WZ3w4cXCAyNZ9AqM-w0OzLM8XecoRvBHSIDEMgJ4lh1Tr32rjLCx2UaCsALtDecTJqWjPpKHazWyjawB_ecEi4WGezDDy6Cok5DubgBn1_X2fx3vqpVaTrWsTpTh_lyJ_rPpHDe_UDZ_Z6qXtX3s8qXWv9W5jWvBJSrDaFoJ29dJNp5xQgu9I4D6xOfz4cMe)  
password : lorem

[JPG file](https://nicopowa.github.io/urlock/test.html)  
password : test


## Links

- [MDN URL Fragment](https://developer.mozilla.org/docs/Web/URI/Reference/Fragment)
- [IETF URL Fragment](https://datatracker.ietf.org/doc/html/rfc3986#section-3.5)