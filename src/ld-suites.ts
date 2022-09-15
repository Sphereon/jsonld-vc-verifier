import {
  ICredential,
  IPresentation,
  IVerifiableCredential,
} from "@sphereon/ssi-types";
import { IKey, IKeyManager, TKeyType } from "@veramo/core";
import { DIDDocument } from "did-resolver/src/resolver";

export abstract class SphereonLdSignature {
  // LinkedDataSignature Suites according to
  // https://github.com/digitalbazaar/jsonld-signatures/blob/main/lib/suites/LinkedDataSignature.js
  // Add type definition as soon as https://github.com/digitalbazaar/jsonld-signatures
  // supports those.

  abstract getSupportedVerificationType(): string;

  abstract getSupportedVeramoKeyType(): TKeyType;

  abstract getSuiteForSigning(
    key: IKey,
    issuerDid: string,
    verificationMethodId: string,
    keyManager: Pick<IKeyManager, "keyManagerGet" | "keyManagerSign">
  ): any;

  abstract getContext(): string;

  abstract getSuiteForVerification(): any;

  abstract preDidResolutionModification(
    didUrl: string,
    didDoc: DIDDocument
  ): void;

  abstract preSigningCredModification(credential: ICredential): void;

  abstract preVerificationCredModification(
    credential: IVerifiableCredential
  ): void;

  preSigningPresModification(presentation: IPresentation): void {
    // TODO: Remove invalid field 'verifiers' from Presentation. Needs to be adapted for LD credentials
    // Only remove empty array (vc.signPresentation will throw then)
    const sanitizedPresentation = presentation as any;
    if (sanitizedPresentation?.verifier?.length == 0) {
      delete sanitizedPresentation.verifier;
    }
  }
}
