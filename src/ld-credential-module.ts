import { purposes } from "@digitalcredentials/jsonld-signatures";
import * as vc from "@digitalcredentials/vc";
import { BbsBlsSignature2020 } from "@mattrglobal/jsonld-signatures-bbs";
import {
  IVerifiableCredential,
  IVerifiablePresentation,
} from "@sphereon/ssi-types";
import Debug from "debug";

import { LdContextLoader } from "./ld-context-loader";
import { LdDocumentLoader } from "./ld-document-loader";
import { LdSuiteLoader } from "./ld-suite-loader";
import { IResolver } from "./resolver";

//Support for Typescript added in version 9.0.0
// eslint-disable-next-line @typescript-eslint/no-var-requires
const jsonld = require("jsonld-signatures");

const ProofPurpose = purposes.ProofPurpose;
const AssertionProofPurpose = purposes.AssertionProofPurpose;
const AuthenticationProofPurpose = purposes.AuthenticationProofPurpose;

const debug = Debug("sphereon:ld-credential-module");

export class LdCredentialModule {
  /**
   * TODO: General Implementation Notes
   * - (SOLVED) EcdsaSecp256k1Signature2019 (Signature) and EcdsaSecp256k1VerificationKey2019 (Key)
   * are not useable right now, since they are not able to work with blockChainId and ECRecover.
   * - DID Fragment Resolution.
   * - Key Manager and Verification Methods: Veramo currently implements no link between those.
   */

  ldSuiteLoader: LdSuiteLoader;
  private ldDocumentLoader: LdDocumentLoader;

  constructor(options: {
    ldContextLoader: LdContextLoader;
    ldSuiteLoader: LdSuiteLoader;
  }) {
    this.ldSuiteLoader = options.ldSuiteLoader;
    this.ldDocumentLoader = new LdDocumentLoader(options);
  }

  async verifyCredential(
    credential: IVerifiableCredential,
    resolver: IResolver,
    fetchRemoteContexts = false,
    purpose: typeof ProofPurpose = new AssertionProofPurpose(),
    // eslint-disable-next-line @typescript-eslint/ban-types
    checkStatus?: Function
  ): Promise<boolean> {
    const verificationSuites = this.getAllVerificationSuites();
    this.ldSuiteLoader
      .getAllSignatureSuites()
      .forEach((suite) => suite.preVerificationCredModification(credential));
    let result;
    if (Array.isArray(credential.proof)) {
      //TODO handle LinkedDataProofChain
      throw Error("LinkedDataProofChain is not implemented");
    } else {
      if (credential.proof.type === "BbsBlsSignature2020") {
        //Should never be null or undefined
        const suite = this.ldSuiteLoader
          .getAllSignatureSuites()
          .find((s) => s.getSupportedVeramoKeyType() === "Bls12381G2")
          ?.getSuiteForVerification() as BbsBlsSignature2020;
        result = await jsonld.verify(credential, {
          suite,
          purpose: purpose,
          documentLoader: this.ldDocumentLoader.getLoader(
            resolver,
            fetchRemoteContexts
          ),
        });
      } else {
        result = await vc.verifyCredential({
          credential,
          suite: verificationSuites,
          documentLoader: this.ldDocumentLoader.getLoader(
            resolver,
            fetchRemoteContexts
          ),
          purpose: purpose,
          compactProof: false,
          checkStatus: checkStatus,
        });
      }
      if (result.verified) return true;

      debug(
        `Error verifying LD Verifiable Credential: ${JSON.stringify(
          result,
          null,
          2
        )}`
      );
      debug(JSON.stringify(result, null, 2));
      throw Error("Error verifying LD Verifiable Credential");
    }
  }

  private getAllVerificationSuites() {
    return this.ldSuiteLoader
      .getAllSignatureSuites()
      .map((x) => x.getSuiteForVerification());
  }

  async verifyPresentation(
    presentation: IVerifiablePresentation,
    challenge: string | undefined,
    domain: string | undefined,
    resolver: IResolver,
    fetchRemoteContexts = false,
    presentationPurpose: typeof ProofPurpose = !challenge && !domain
      ? new AssertionProofPurpose()
      : new AuthenticationProofPurpose(domain, challenge),
    // eslint-disable-next-line @typescript-eslint/ban-types
    checkStatus?: Function
  ): Promise<boolean> {
    let result;
    if (Array.isArray(presentation.proof)) {
      //TODO implement LinkedDataProofChain
      throw new Error("LinkedDataProofChain not implemented");
    } else {
      if (presentation.proof.type === "BbsBlsSignature2020") {
        //Should never be null or undefined
        const suite = this.ldSuiteLoader
          .getAllSignatureSuites()
          .find((s) => s.getSupportedVeramoKeyType() === "Bls12381G2")
          ?.getSuiteForVerification() as BbsBlsSignature2020;
        result = await jsonld.verify(presentation, {
          suite,
          purpose: presentationPurpose,
          documentLoader: this.ldDocumentLoader.getLoader(
            resolver,
            fetchRemoteContexts
          ),
        });
      } else {
        result = await vc.verify({
          presentation,
          suite: this.getAllVerificationSuites(),
          documentLoader: this.ldDocumentLoader.getLoader(
            resolver,
            fetchRemoteContexts
          ),
          challenge,
          domain,
          presentationPurpose,
          compactProof: false,
          checkStatus,
        });
      }

      if (result.verified) return true;

      debug(`Error verifying LD Verifiable Presentation`);
      debug(JSON.stringify(result, null, 2));
      throw Error("Error verifying LD Verifiable Presentation");
    }
  }
}
