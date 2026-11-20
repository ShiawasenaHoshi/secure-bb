// The skills module's window onto bb: real SDK calls only (`bb.sdk.skills.*`, the API behind `bb skill ...`).
import type { BbPluginApi } from "@get-bb/plugin-sdk";
import type { SkillFileSource, SkillRef } from "./types.js";

type Sdk = BbPluginApi["sdk"];

/** Only `id` and `projectId` matter to bb's endpoints; `environmentId` is null (the machine bb runs on). */
export function bbSkillSource(sdk: Sdk): SkillFileSource {
  const where = (ref: Pick<SkillRef, "id" | "projectId">) => ({ projectId: ref.projectId, environmentId: null, skillId: ref.id });
  return {
    async listFiles(ref) {
      return sdk.skills.listFiles(where(ref));
    },
    async readFile(ref, path) {
      return sdk.skills.getContent({ ...where(ref), path });
    },
    async remove(ref) {
      await sdk.skills.remove({ projectId: ref.projectId, environmentId: null, skillId: ref.id });
    },
  };
}
