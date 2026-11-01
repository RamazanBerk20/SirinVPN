import { afterEach, expect, it } from "vitest";
import { pseudoLocale, setLocale, sourceLocale } from "../i18n";
import { errorMessage } from "./errors";

afterEach(() => setLocale(sourceLocale));

it("names the failed action, then the backend cause in English, and the localized summary otherwise", () => {
  expect(errorMessage(new Error("Port 22 refused the connection."), "Couldn’t connect.")).toBe("Couldn’t connect. Port 22 refused the connection.");
  expect(errorMessage(new Error("Couldn’t connect. Port 22 refused."), "Couldn’t connect.")).toBe("Couldn’t connect. Port 22 refused.");
  expect(errorMessage(new Error("Port 22 refused the connection."), "Couldn’t connect. Try again.")).toBe("Couldn’t connect. Port 22 refused the connection.");
  expect(errorMessage("", "Couldn’t connect.")).toBe("Couldn’t connect.");
  expect(errorMessage(undefined, "Couldn’t connect.")).toBe("Couldn’t connect.");
  setLocale(pseudoLocale);
  expect(errorMessage(new Error("Port 22 refused the connection."), "Localized summary")).toBe("Localized summary");
});
