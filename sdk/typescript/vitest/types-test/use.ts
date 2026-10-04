// The matchers, as a test file uses them: types.sh compiles this against each Vitest the package supports.
import { expect } from "vitest";
import { asUser, matchers } from "@rowstile/vitest";

expect.extend(matchers);

export async function uses(rename: () => Promise<void>, error: unknown): Promise<void> {
  await expect(asUser("2", rename)).rejects.toBeRefused("update", "folder.edit");
  await expect(asUser("2", rename)).rejects.toBeRefused();
  await expect(rename()).rejects.toBeNotFound();
  expect(error).toBeRefused("insert");
  expect(error).not.toBeNotFound();
  // @ts-expect-error: a matcher rowstile doesn't have
  expect(error).toBeRefusd();
  // @ts-expect-error: its arguments are strings
  expect(error).toBeRefused(1);
}
