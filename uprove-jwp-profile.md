# U-Prove JWP Profile

This document contains text to be integrated in the JWP documents (26 April 2023 version).

# JSON Web Proof [(link)](https://json-web-proofs.github.io/json-web-proofs/draft-ietf-jose-json-web-proof.html)

TODO

# JSON Proof Algorithms [(link)](https://json-web-proofs.github.io/json-web-proofs/draft-ietf-jose-json-proof-algorithms.html)

*(for section 6)*

## U-Prove

U-Prove is a credential scheme that supports unlinkability and selective disclosure, detailed in the [U-Prove Cryptographic Specification v1.1.5](https://github.com/microsoft/uprove-node-reference/blob/main/doc/U-Prove%20Cryptographic%20Specification%20V1.1%20Revision%205.pdf), using a blind signature scheme defined in [ISO/IEC 18370-2:2016](https://www.iso.org/standard/62544.html). This profile makes use of the JSON-encoded artifacts defined in the [U-Prove JSON framework (UPJF)](https://github.com/microsoft/uprove-node-reference/blob/main/doc/U-Prove_JSON_Framework.md). (*NOTE*: consider decoupling from the UPJF, and specify directly using the crypto spec, to avoid the friction points.)

The U-Prove (capitalized) *Issuer*, *Prover*, and *Verifier* roles correspond to the JWP's (lowercased) *issuer*, *holder*, and *verifier* ones, respectively. Moreover, U-Prove *attributes* correspond to JSON *claims*.


### Setup

The issuer sets up its public parameters, as described in the [UPJF](https://github.com/microsoft/uprove-node-reference/blob/main/doc/U-Prove_JSON_Framework.md#issuer-parameters). If the U-Prove tokens are to contain attributes (claims), their types SHOULD be encoded in the parameters' `spec` field using a `claims` array (as in a [JPT header](https://json-web-proofs.github.io/json-web-proofs/draft-ietf-jose-json-proof-token.html#name-claims)).

Here is an example of a set of Issuer parameters encoded as a JSON Web Key (JWK):
```
{
  kty: 'UP',
  alg: 'UP256',
  kid: 'UUbAKVRmLuswULmn1ig057cDOy7fGQE5ar3iz2hVxwY',
  g0: 'BMmF8Ej5gOCTL2J0YYZz2wcPY_RoTJ2SzYkBeKr3AdQO1b-H3JyCtiDvkcbRaOd_A94f7oWBhKg_iHuvBBak85Y',
  spec: 'eyJuIjo0LCJleHBUeXBlIjoiZGF5IiwiYXR0clR5cGVzIjpbImZhbWlseV9uYW1lIiwiZ2l2ZW5fbmFtZSIsImVtYWlsIiwiYWdlIl19'
}
```

and its corresponding public key $y_0$: `PKinssR-9gt4ZSFDb1-nCIuochODYmji2W3o3BDSgEQ`. The specification property `spec` encodes the following JSON object, specifying the number of attributes in to-be-issued tokens (e.g., 4), the expiration type (e.g., number of days since Unix epoch), and attribute types (e.g., family name, given name, email address, and age):
```
{
  n: 4,
  expType: 'day',
  attrTypes: [ 'family_name', 'given_name', 'email', 'age' ]
}
```

### Issue

The issuer and holder perform the U-Prove issuance protocol, as described in the [UPJF](https://github.com/microsoft/uprove-node-reference/blob/main/doc/U-Prove_JSON_Framework.md#issuance-protocol), resulting in one or more U-Prove tokens. Although not necessary, the tokens can be serialized as JWP in issued form using the following format (an application might prefer to optimize storage of multiple tokens encoding the same attributes using a different scheme):

* `protected` header: contains a `typ` property with value "JPT" and an `alg` property with a value matching the one in the Issuer parameters (either "UP256", "UP384", "UP521")
* `payload`: an array of the attribute values encoded in the token
* `proof`:  a JSON object encoding the U-Prove token, as described in the [UPJF](https://github.com/microsoft/uprove-node-reference/blob/main/doc/U-Prove_JSON_Framework.md#u-prove-token)

Here is an example of a U-Prove token issued using the example Issuer parameters, encoding the attribute values "Doe", "Jay", "jaydoe@example.org", "42" (corresponding to the attribute types specified in the Issuer parameters).

```
{
  protected: { alg: 'UP256', typ: 'JWP' },
  payload: [ 'RG9l', 'SmF5', 'amF5ZG9lQGV4YW1wbGUub3Jn', 'NDI' ],
  proof: {
    UIDP: 'UUbAKVRmLuswULmn1ig057cDOy7fGQE5ar3iz2hVxwY',
    h: 'BDs-SvWyG5e0VZhB9mqkvJJxyztAtnedXWq3yuGJ_qAjtWCYTfl8WMwlQNMf_lAI4Qjde9vnaRB-n9Fnc9WMzxA',
    TI: 'eyJpc3MiOiJodHRwczovL2lzc3VlciIsImV4cCI6MTk1MjJ9',
    PI: '',
    sZp: 'BA1NzNrZrnzVWjo2rKEagfXZ_aK4kvMe3F31jPltiY_aZgLSz4tFFnSnMzjEzQVbTpwZwvLY4PbuvxiYy7a7NiQ',
    sCp: 'OFPTG4fJhVXFYqFnGOvarbIGxsvr3ENw4QqWqwdfZY8',
    sRp: 'qlk-fxjzTaneNcTckQalEwzmvD8mn7v9WINT_m_TC4k'
  }
}
```

and the corresponding private key $\alpha^{-1}$: `2VXSUN55TDcgrPOlPlNXg1dvEzqSoTLLd7hOUaTr5ZY`.

Its compact representation is:
```
eyJhbGciOiJVUDI1NiIsInR5cCI6IkpXUCJ9.WyJSRzlsIiwiU21GNSIsImFtRjVaRzlsUUdWNFlXMXdiR1V1YjNKbiIsIk5ESSJd.eyJVSURQIjoiVVViQUtWUm1MdXN3VUxtbjFpZzA1N2NET3k3ZkdRRTVhcjNpejJoVnh3WSIsImgiOiJCRHMtU3ZXeUc1ZTBWWmhCOW1xa3ZKSnh5enRBdG5lZFhXcTN5dUdKX3FBanRXQ1lUZmw4V013bFFOTWZfbEFJNFFqZGU5dm5hUkItbjlGbmM5V016eEEiLCJUSSI6ImV5SnBjM01pT2lKb2RIUndjem92TDJsemMzVmxjaUlzSW1WNGNDSTZNVGsxTWpKOSIsIlBJIjoiIiwic1pwIjoiQkExTnpOclpybnpWV2pvMnJLRWFnZlhaX2FLNGt2TWUzRjMxalBsdGlZX2FaZ0xTejR0RkZuU25NempFelFWYlRwd1p3dkxZNFBidXZ4aVl5N2E3TmlRIiwic0NwIjoiT0ZQVEc0ZkpoVlhGWXFGbkdPdmFyYklHeHN2cjNFTnc0UXFXcXdkZlpZOCIsInNScCI6InFsay1meGp6VGFuZU5jVGNrUWFsRXd6bXZEOG1uN3Y5V0lOVF9tX1RDNGsifQ
```

### Confirm

A holder can confirm the validity of issued U-Prove tokens by verifying the Issuer's signature during the U-Prove issuance protocol, in the [Issue](#issue) operation.

### Present

The holder presents a U-Prove JPT by performing the presentation protocol, as described in the [UPJF](https://github.com/microsoft/uprove-node-reference/blob/main/doc/U-Prove_JSON_Framework.md#presentation-protocol).

The issued U-Prove JPT's can be transformed into the presented form by:
* removing the undisclosed attributes from the `payload` property
* adding a `presented` property encoding the following property:
   * the commitment value `a`
   * the responses array `r` for undisclosed attributes,
   * a base64url-encoding of the presentation message `m`

Here is an example of the presented for of the above U-Prove token, disclosing the given name and age attributes, and signing the nonce `uTEB371l1pzWJl7afB0wi0HWUNk1Le-bComFLxa8K-s` using the token's private key.

```
{
  protected: { alg: 'UP256', typ: 'JWP' },
  payload: [ null, 'SmF5', null, 'NDI' ],
  proof: {
    UIDP: 'UUbAKVRmLuswULmn1ig057cDOy7fGQE5ar3iz2hVxwY',
    h: 'BDs-SvWyG5e0VZhB9mqkvJJxyztAtnedXWq3yuGJ_qAjtWCYTfl8WMwlQNMf_lAI4Qjde9vnaRB-n9Fnc9WMzxA',
    TI: 'eyJpc3MiOiJodHRwczovL2lzc3VlciIsImV4cCI6MTk1MjJ9',
    PI: '',
    sZp: 'BA1NzNrZrnzVWjo2rKEagfXZ_aK4kvMe3F31jPltiY_aZgLSz4tFFnSnMzjEzQVbTpwZwvLY4PbuvxiYy7a7NiQ',
    sCp: 'OFPTG4fJhVXFYqFnGOvarbIGxsvr3ENw4QqWqwdfZY8',
    sRp: 'qlk-fxjzTaneNcTckQalEwzmvD8mn7v9WINT_m_TC4k'
  },
  presented: {
    a: 'GN3JwqzLTN_CxUmP_1o9Bm0ZDBFNKPJeStwmU0oP7wY',
    r: [
      '7BQKoBhpDc_vliNUCjev2Pr5zmHIWuemdpPdcp8RjE4',
      '-hNfGQfP_J7PCAYx0iU1FqbYHcrzoACMnYYIRYU47TY',
      'ysXJ8U1CQQesqMbletc9xhKwUuSalIBgpKQcsix8IOc'
    ],
    m: 'dVRFQjM3MWwxcHpXSmw3YWZCMHdpMEhXVU5rMUxlLWJDb21GTHhhOEstcw'
  }
}
```

It's compact representation is:
```
eyJhbGciOiJVUDI1NiIsInR5cCI6IkpXUCJ9.W251bGwsIlNtRjUiLG51bGwsIk5ESSJd.eyJVSURQIjoiVVViQUtWUm1MdXN3VUxtbjFpZzA1N2NET3k3ZkdRRTVhcjNpejJoVnh3WSIsImgiOiJCRHMtU3ZXeUc1ZTBWWmhCOW1xa3ZKSnh5enRBdG5lZFhXcTN5dUdKX3FBanRXQ1lUZmw4V013bFFOTWZfbEFJNFFqZGU5dm5hUkItbjlGbmM5V016eEEiLCJUSSI6ImV5SnBjM01pT2lKb2RIUndjem92TDJsemMzVmxjaUlzSW1WNGNDSTZNVGsxTWpKOSIsIlBJIjoiIiwic1pwIjoiQkExTnpOclpybnpWV2pvMnJLRWFnZlhaX2FLNGt2TWUzRjMxalBsdGlZX2FaZ0xTejR0RkZuU25NempFelFWYlRwd1p3dkxZNFBidXZ4aVl5N2E3TmlRIiwic0NwIjoiT0ZQVEc0ZkpoVlhGWXFGbkdPdmFyYklHeHN2cjNFTnc0UXFXcXdkZlpZOCIsInNScCI6InFsay1meGp6VGFuZU5jVGNrUWFsRXd6bXZEOG1uN3Y5V0lOVF9tX1RDNGsifQ.eyJhIjoiR04zSndxekxUTl9DeFVtUF8xbzlCbTBaREJGTktQSmVTdHdtVTBvUDd3WSIsInIiOlsiN0JRS29CaHBEY192bGlOVUNqZXYyUHI1em1ISVd1ZW1kcFBkY3A4UmpFNCIsIi1oTmZHUWZQX0o3UENBWXgwaVUxRnFiWUhjcnpvQUNNbllZSVJZVTQ3VFkiLCJ5c1hKOFUxQ1FRZXNxTWJsZXRjOXhoS3dVdVNhbElCZ3BLUWNzaXg4SU9jIl0sIm0iOiJkVlJGUWpNM01Xd3hjSHBYU213M1lXWkNNSGRwTUVoWFZVNXJNVXhsTFdKRGIyMUdUSGhoT0VzdGN3In0
```

### Verify

The verifier verifies the presented U-Prove JWP by running the U-Prove presentation proof verification.

# JSON Proof Token [(link)](https://json-web-proofs.github.io/json-web-proofs/draft-ietf-jose-json-proof-token.html)

TODO