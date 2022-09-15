import { DIDDocumentSection, ResolveDidArgs } from "@veramo/core";
import {
  DIDDocComponent,
  GetDIDComponentArgs,
} from "@veramo/core/src/types/IResolver";
import Debug from "debug";
import {
  DIDDocument,
  DIDResolutionOptions,
  DIDResolutionResult,
  parse as parseDID,
  Resolvable,
  ServiceEndpoint,
  VerificationMethod,
} from "did-resolver";

const debug = Debug("sphereon:DIDResolver");

interface Options {
  resolver: Resolvable;
}

export interface IResolver {
  resolveDid(args: ResolveDidArgs): Promise<DIDResolutionResult>;
  getDIDComponentById(args: GetDIDComponentArgs): Promise<DIDDocComponent>;
}

export class DIDResolver implements IResolver {
  private didResolver: Resolvable;

  constructor(options: Options) {
    if (!options.resolver) throw Error("Missing resolver");
    this.didResolver = options.resolver;
  }

  async resolveDid({
    didUrl,
    options,
  }: {
    didUrl: string;
    options?: DIDResolutionOptions;
  }): Promise<DIDResolutionResult> {
    debug("Resolving %s", didUrl);
    const resolverOptions = {
      accept: "application/did+ld+json",
      ...options,
    };

    // ensure the required fields are present, even if the resolver is not compliant
    const cannedResponse: DIDResolutionResult = {
      didDocumentMetadata: {},
      didResolutionMetadata: {},
      didDocument: null,
    };

    const resolution = await this.didResolver.resolve(didUrl, resolverOptions);

    return {
      ...cannedResponse,
      ...resolution,
    };
  }

  async getDIDComponentById({
    didDocument,
    didUrl,
    section,
  }: {
    didDocument: DIDDocument;
    didUrl: string;
    section?: DIDDocumentSection;
  }): Promise<VerificationMethod | ServiceEndpoint> {
    debug("Resolving %s", didUrl);
    const did = parseDID(didUrl)?.did || didDocument.id;
    const doc = didDocument;
    const mainSections = [
      ...(doc.verificationMethod || []),
      ...(doc.publicKey || []),
      ...(doc.service || []),
    ];
    const subsection = section ? [...(doc[section] || [])] : mainSections;

    let result = subsection.find((item) => {
      if (typeof item === "string") {
        return item === didUrl || `${did}${item}` === didUrl;
      } else {
        return item.id === didUrl || `${did}${item.id}` === didUrl;
      }
    });
    if (typeof result === "string") {
      result = mainSections.find(
        (item) => item.id === didUrl || `${did}${item.id}` === didUrl
      );
    }

    if (!result) {
      const err = `not_found: DID document fragment (${didUrl}) could not be located.`;
      debug(err);
      throw new Error(err);
    } else if (result.id.startsWith("#")) {
      // fix did documents that use only the fragment part as key ID
      result.id = `${did}${result.id}`;
    }
    return result;
  }
}
