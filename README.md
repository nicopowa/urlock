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

[Lorem Ipsum](https://nicopowa.github.io/urlock/#lorem%20ipsum|_JvzIHAFbBq7mSWJ8ilEKtwjpTlOr239tb_vzKKBHhU8HwQ_kZoNe65nZOOzPI2UlMuAP5RWOgP-6nT7sLPkVTIJWfa9WP3nc53ecxNgs4f8eQhhOaxbWNgz__BpLisO-P9IShEIpSc0cGfBxObShbnDnkitQVfuHVYkdCua5o6OKpZ31JgIUOmIfiu39HupOa5cW5mxkXi9-BjGnMTN8HuTW_kE6yd0hCSOmv73zXcyIjIos3DATL3ZGUZCdI479xLixcpNrlGHixFXOCWlVUqmkSmAWQkzjRGeu1Qw9_UCF2_Q0-9RMNKtvt89yViLuZtvCOhe5ZjGLSIlpAe3_VzLB2rJQ0-Ade1Fxq9L1SgSoSdybkFI5E3nmezwvh0iHLwrP4M9d2dzhHynkYTC7vo4PqvKjxU4jlu1hVircKA0)  
password : lorem

[JPG file](https://nicopowa.github.io/urlock/test.html)  
password : test


## Links

- [MDN URL Fragment](https://developer.mozilla.org/docs/Web/URI/Reference/Fragment)
- [IETF URL Fragment](https://datatracker.ietf.org/doc/html/rfc3986#section-3.5)