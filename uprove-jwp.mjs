import * as uprove from 'uprove-node-reference/js/src/uprove.js';
import * as UPJF from 'uprove-node-reference/js/src/upjf.js';
import * as serialization from 'uprove-node-reference/js/src/serialization.js';

export const toBase64Url = (a) => Buffer.from(a).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''); // FIXME: isn't base64url encoding supported?
export const fromBase64Url = (b64) => Buffer.from(b64, 'base64');

const UPJFIssuerSetup = (descGq, attributes) => {
    // The issuer parameters specification
    const spec = {
        n: attributes.length,
        expType: UPJF.ExpirationType.day,
    }
    console.log("Issuer specification", spec);
    // add the attribute field names to the specification
    if (attributes.length > 0) {
        spec.attrTypes = attributes;
    }
    console.log("Issuer specification", spec);
    // Issuer creates its parameters set, and encodes them as a JWK
    const ikp = UPJF.createIssuerKeyAndParamsUPJF(descGq, spec, undefined);
    const jwk = UPJF.encodeIPAsJWK(ikp.ip);
    console.log("Issuer JWK", jwk);
    console.log("Issuer key", UPJF.encodePrivateKeyAsBase64Url(ikp.y0));

    // Issuer publishes the JWK at its well-known URL: [IssuerURL]/.well-known/jwks.json
    const issuerURL = "https://issuer";

    return {
        ikp: ikp,
        jwk: jwk,
        issuerUrl: issuerURL
    };
}


// performs the issuance of a batch of U-Prove tokens
const UPJFTokenIssuance = (id, ip, attributes) => {

    // token information contains always-disclosed data
    const spec = UPJF.parseSpecification(ip.S);
    const TI = UPJF.encodeTokenInformation({
        iss: id.issuerUrl,
        exp: UPJF.getExp(spec.expType, 7) // 7-day expiration
    })

    // number of tokens to issue in batch
    const numberOfTokens = 1;

    // setup participants
    const issuer = new uprove.Issuer(id.ikp, attributes, TI, numberOfTokens);
    const prover = new uprove.Prover(ip, attributes, TI, new Uint8Array(), numberOfTokens);

    // issuer creates the first message
    const message1 = serialization. encodeFirstIssuanceMessage(
        issuer.createFirstMessage());

    // prover creates the second message
    const message2 = serialization.encodeSecondIssuanceMessage(
        prover.createSecondMessage(
            serialization.decodeFirstIssuanceMessage(ip, message1)));

    // issuer creates the third message
    const message3 = serialization.encodeThirdIssuanceMessage(
        issuer.createThirdMessage(
            serialization.decodeSecondIssuanceMessage(ip, message2)));

    // prover creates the U-Prove Access tokens
    const uproveKeysAndTokens = prover.createTokens(
        serialization.decodeThirdIssuanceMessage(ip, message3));

    return uproveKeysAndTokens;

}

const JWPSample = () => {

    console.log("U-Prove JWP profile sample run");

    // Issuer creates its Issuer parameters
    const claimTypes = ["family_name", "given_name", "email", "age"];
    const issuerSetup = UPJFIssuerSetup(uprove.ECGroup.P256, claimTypes);

    // Prover and Verifier retrieve the JWK from the well-known URL, and parse and verify the Issuer params
    const ip = UPJF.decodeJWKAsIP(issuerSetup.jwk);
    ip.verify();
    // Prover requests Bare U-Prove tokens from the Issuer
    const attributes = ["Doe", "Jay", "jaydoe@example.org", "42"].map(a => Buffer.from(a, "utf-8")); // TODO: encode 42 directly, to allow predicate proof
    const encodedAttributes = attributes.map(A => toBase64Url(A));
    const uproveKeysAndTokens = UPJFTokenIssuance(issuerSetup, ip, attributes);
    console.log("U-Prove token private key", UPJF.encodePrivateKeyAsBase64Url(uproveKeysAndTokens[0].alphaInverse));
    const uproveToken = serialization.encodeUProveToken(uproveKeysAndTokens[0].upt);
    const issuedJWP = {
        protected: {
            alg: issuerSetup.jwk.alg,
            typ: "JWP"
        },
        payload: encodedAttributes,
        proof: uproveToken
    }
    console.log("issued JWP", issuedJWP);
    // create the compact serialization of the issued JWP
    const compactIssuedJWP = [issuedJWP.protected, issuedJWP.payload, issuedJWP.proof]
    .map(x => toBase64Url(Buffer.from(JSON.stringify( x ))))
    .join(".");
    console.log("compact issued JWP", compactIssuedJWP);

    // To later present a token to the Verifier, the Prover obtains a challenge (nonce) from the Verifier
    // and creates a presentation proof disclosing the first_name and age attributes;
    const nonce = "uTEB371l1pzWJl7afB0wi0HWUNk1Le-bComFLxa8K-s"; // same nonce as BBS example
    const presentationChallenge = Buffer.from(nonce, "utf-8");
    const disclosedAttributes = [2,4];
    const proof = serialization.encodePresentationProof(
        uprove.generatePresentationProof(ip, [2,4], uproveKeysAndTokens[0], presentationChallenge, attributes).pp);
    const presentedJWP = issuedJWP;
    presentedJWP.payload = presentedJWP.payload.map((v, i, a) => disclosedAttributes.includes(i+1) ? v : null); 
    presentedJWP.presented = {
        a: proof.a,
        r: proof.r,
        m: toBase64Url(presentationChallenge)
    }
    console.log("presented JWP", presentedJWP);
    // create the compact serialization of the issued JWP
    const compactPresentedJWP = [presentedJWP.protected, presentedJWP.payload, presentedJWP.proof, presentedJWP.presented]
    .map(x => toBase64Url(Buffer.from(JSON.stringify( x ))))
    .join(".");
    console.log("compact presented JWP", compactPresentedJWP);

    // The Verifier validates the token and presentation proof
    const upt = serialization.decodeUProveToken(ip, presentedJWP.proof);
    uprove.verifyTokenSignature(ip, upt);
    const spec = UPJF.parseSpecification(ip.S);
    const tokenInfo = UPJF.parseTokenInformation(upt.TI);
    if (UPJF.isExpired(spec.expType, tokenInfo.exp)) {
        throw "token is expired";
    }
    const A = {};
    presentedJWP.payload.forEach((v,i,a) => {
        if (v !== null) {
            A[i+1] = v;
        }
    })
    const presentationProof = {
        A: A,
        a: presentedJWP.presented.a,
        r: presentedJWP.presented.r
    }
    
    uprove.verifyPresentationProof(
        ip,
        upt,
        fromBase64Url(presentedJWP.presented.m),
        serialization.decodePresentationProof(ip, presentationProof));
    console.log("Success");
}

try {
    JWPSample();
} catch (e) {
    console.log("Error", e);
}
