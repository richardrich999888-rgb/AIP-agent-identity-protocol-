import type { Meta, StoryObj } from "@storybook/react-vite";
import { expect, userEvent, waitFor, within } from "storybook/test";
import { NativeResearchPanel } from "../src/ui/research/NativeResearchPanel";

const meta = {
  title: "Accountability/Research archive verification",
  component: NativeResearchPanel,
} satisfies Meta<typeof NativeResearchPanel>;
export default meta;
type Story = StoryObj<typeof meta>;
export const AwaitingVerification: Story = {};
export const VerifiedCapture: Story = {
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    await userEvent.click(
      canvas.getByRole("button", { name: "Run upstream verifier" }),
    );
    await waitFor(
      () =>
        expect(
          canvas.getByText("Signature verified", { exact: true }),
        ).toBeVisible(),
      { timeout: 30000 },
    );
  },
};
export const ChangedByte: Story = {
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    await userEvent.selectOptions(
      canvas.getByLabelText("Integrity check"),
      "tampered",
    );
    await userEvent.click(
      canvas.getByRole("button", { name: "Run upstream verifier" }),
    );
    await waitFor(
      () =>
        expect(
          canvas.getByText("Evidence rejected", { exact: true }),
        ).toBeVisible(),
      { timeout: 30000 },
    );
  },
};
