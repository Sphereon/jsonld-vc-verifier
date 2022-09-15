import { getResolver } from "@sphereon/ssi-sdk-bls-did-resolver-key";
import {
  IVerifiableCredential,
  IVerifiablePresentation,
} from "@sphereon/ssi-types";
import { Resolver } from "did-resolver";

import {
  LdCredentialModule,
  SphereonBbsBlsSignature2020,
  SphereonEcdsaSecp256k1RecoverySignature2020,
  SphereonEd25519Signature2018,
  SphereonEd25519Signature2020,
} from "../index";
import { LdContextLoader } from "../ld-context-loader";
import { LdDefaultContexts } from "../ld-default-contexts";
import { LdSuiteLoader } from "../ld-suite-loader";
import { DIDResolver } from "../resolver";
import { AssertionProofPurpose } from "../types/types";

let ldCredentialModule: LdCredentialModule;
let didResolver: DIDResolver;

beforeAll(() => {
  ldCredentialModule = new LdCredentialModule({
    ldContextLoader: new LdContextLoader({
      contextsPaths: [LdDefaultContexts],
    }),
    ldSuiteLoader: new LdSuiteLoader({
      ldSignatureSuites: [
        new SphereonBbsBlsSignature2020(),
        new SphereonEd25519Signature2018(),
        new SphereonEd25519Signature2020(),
        new SphereonEcdsaSecp256k1RecoverySignature2020(),
      ],
    }),
  });
  didResolver = new DIDResolver({
    resolver: new Resolver({ ...getResolver() }),
  });
});

const vc: IVerifiableCredential = {
  issuer:
    "did:key:zUC7HWLPKu1j5EGvD23pv8PHdYKB2nJykXVngbbBmxfCb6fbgLMgA32FdA6zntaZYEMmxqJKg3Hj1Mas4AtpsfcFSuckJZ4cvudYSRvrZhwAjG2zqZSAUpLsy482xWAtkCSNUk2",
  credentialSubject: {
    id: "did:key:zUC7HWLPKu1j5EGvD23pv8PHdYKB2nJykXVngbbBmxfCb6fbgLMgA32FdA6zntaZYEMmxqJKg3Hj1Mas4AtpsfcFSuckJZ4cvudYSRvrZhwAjG2zqZSAUpLsy482xWAtkCSNUk2",
  },
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/security/bbs/v1",
  ],
  type: ["VerifiableCredential"],
  issuanceDate: "2022-08-26T12:12:38.686Z",
  proof: {
    type: "BbsBlsSignature2020",
    created: "2022-08-26T12:12:38Z",
    proofPurpose: "assertionMethod",
    proofValue:
      "jR9m+FN4tJpS5TCJ2N/0TgGS/Dy9NmwaBB7Bq+xdzGg3kPuvoldPEoXee1Pc09MvOZ9BxmaJGb63a7WWnxKlSkjw4j8mkABFQ6pvH3VGEitnCSC9/6snEHRmvJjWm96u25NOMaHsq8tyHZD8/Z+W1A==",
    verificationMethod:
      "did:key:zUC7HWLPKu1j5EGvD23pv8PHdYKB2nJykXVngbbBmxfCb6fbgLMgA32FdA6zntaZYEMmxqJKg3Hj1Mas4AtpsfcFSuckJZ4cvudYSRvrZhwAjG2zqZSAUpLsy482xWAtkCSNUk2#zUC7HWLPKu1j5EGvD23pv8PHdYKB2nJykXVngbbBmxfCb6fbgLMgA32FdA6zntaZYEMmxqJKg3Hj1Mas4AtpsfcFSuckJZ4cvudYSRvrZhwAjG2zqZSAUpLsy482xWAtkCSNUk2",
  },
};

const vp: IVerifiablePresentation = {
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/security/bbs/v1",
  ],
  holder:
    "did:key:zUC7D5JcgyGpstamM2HPdUq4qgBYsAuL83YDYX2KoeKc2yQL3hoXGthsRcZ77vpqj5hbYPGqQDcWjQ7sxjUcCU41pigHCGfhoF26UxSMkGYs2AjtMK3qNfaVhMiDnkz9jm16CTB",
  verifiableCredential: [
    {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://w3id.org/citizenship/v1",
        "https://w3id.org/security/bbs/v1",
      ],
      id: "https://issuer.oidp.uscis.gov/credentials/83627465",
      type: ["VerifiableCredential", "PermanentResidentCard"],
      issuer:
        "did:key:zUC7D5JcgyGpstamM2HPdUq4qgBYsAuL83YDYX2KoeKc2yQL3hoXGthsRcZ77vpqj5hbYPGqQDcWjQ7sxjUcCU41pigHCGfhoF26UxSMkGYs2AjtMK3qNfaVhMiDnkz9jm16CTB",
      identifier: "83627465",
      name: "Permanent Resident Card",
      description: "Government of Example Permanent Resident Card.",
      issuanceDate: "2019-12-03T12:19:52Z",
      expirationDate: "2029-12-03T12:19:52Z",
      credentialSubject: {
        type: ["PermanentResident", "Person"],
        givenName: "JOHN",
        familyName: "SMITH",
        gender: "Male",
        image: "data:image/png;base64,iVBORw0KGgokJggg==",
        residentSince: "2015-01-01",
        lprCategory: "C09",
        lprNumber: "999-999-999",
        commuterClassification: "C1",
        birthCountry: "Bahamas",
        birthDate: "1958-07-17",
      },
      proof: {
        type: "BbsBlsSignature2020",
        created: "2022-09-14T11:17:53Z",
        proofPurpose: "assertionMethod",
        proofValue:
          "juXt5gGgaqZonU4nTMqXXACZkL3aMb/Qs9e2PNB0C++JAw5g0o7ba49HoMAzRTEeZ3BWVdWvCiWceIladAzeDByWwR6rwlM92AWcrJSb5WRceD1aW8wvYAn74nnrmg/1bpEJulUZWtk26j/6ed28ww==",
        verificationMethod:
          "did:key:zUC7D5JcgyGpstamM2HPdUq4qgBYsAuL83YDYX2KoeKc2yQL3hoXGthsRcZ77vpqj5hbYPGqQDcWjQ7sxjUcCU41pigHCGfhoF26UxSMkGYs2AjtMK3qNfaVhMiDnkz9jm16CTB#zUC7D5JcgyGpstamM2HPdUq4qgBYsAuL83YDYX2KoeKc2yQL3hoXGthsRcZ77vpqj5hbYPGqQDcWjQ7sxjUcCU41pigHCGfhoF26UxSMkGYs2AjtMK3qNfaVhMiDnkz9jm16CTB",
      },
    },
  ],
  type: ["VerifiablePresentation"],
  proof: {
    type: "BbsBlsSignature2020",
    created: "2022-09-14T11:17:53Z",
    proofPurpose: "assertionMethod",
    proofValue:
      "i5b5H31FR7vU41yZ+GC3kmtPw+tOq2JsVLpaHjT35nthbzp0zVTRgxxZj+mZSt5TI2EXrFlui51YKGq/9IIjkS6sphGWBuQBH/TmPDlvu7NUTQ/bwaFCo7iOxme2h3utAXO0o7JnYnuVFZVqiqDvSA==",
    verificationMethod:
      "did:key:zUC7D5JcgyGpstamM2HPdUq4qgBYsAuL83YDYX2KoeKc2yQL3hoXGthsRcZ77vpqj5hbYPGqQDcWjQ7sxjUcCU41pigHCGfhoF26UxSMkGYs2AjtMK3qNfaVhMiDnkz9jm16CTB#zUC7D5JcgyGpstamM2HPdUq4qgBYsAuL83YDYX2KoeKc2yQL3hoXGthsRcZ77vpqj5hbYPGqQDcWjQ7sxjUcCU41pigHCGfhoF26UxSMkGYs2AjtMK3qNfaVhMiDnkz9jm16CTB",
  },
};

describe("ld-credential-module", () => {
  it("should return true verifying a credential", async () => {
    await expect(
      ldCredentialModule.verifyCredential(
        vc,
        didResolver,
        true,
        new AssertionProofPurpose()
      )
    ).resolves.toBeTruthy();
  });

  it("should throw exception verifying a credential", async () => {
    vc.issuer = "did:test";
    await expect(
      ldCredentialModule.verifyCredential(
        vc,
        didResolver,
        true,
        new AssertionProofPurpose()
      )
    ).rejects.toThrow(new Error("Error verifying LD Verifiable Credential"));
  });

  it("should return true verifying a presentation", async () => {
    await expect(
      ldCredentialModule.verifyPresentation(
        vp,
        undefined,
        undefined,
        didResolver,
        true,
        new AssertionProofPurpose()
      )
    ).resolves.toBeTruthy();
  });

  it("should throw exception verifying a presentation", async () => {
    vp.id = "test";
    await expect(
      ldCredentialModule.verifyPresentation(
        vp,
        undefined,
        undefined,
        didResolver,
        true,
        new AssertionProofPurpose()
      )
    ).rejects.toThrow(new Error("Error verifying LD Verifiable Presentation"));
  });
});
