import type { Meta, StoryObj } from "@storybook/react-vite";
import { expect, fn, userEvent, within } from "storybook/test";
import { AS_OF, sensors } from "../src/server/fixtures";
import { SensorCoverage } from "../src/ui/visual/RuntimeMasthead";

const meta = {
  title: "Accountability/Sensor coverage",
  component: SensorCoverage,
  decorators: [
    (Story) => (
      <div style={{ maxWidth: 490 }}>
        <Story />
      </div>
    ),
  ],
  args: {
    meta: { mode: "demo", asOf: AS_OF, source: "Sensor heartbeat fixture" },
    sensors,
    onSensor: fn(),
    onEvidence: fn(),
  },
} satisfies Meta<typeof SensorCoverage>;
export default meta;
type Story = StoryObj<typeof meta>;

export const FleetSnapshot: Story = {
  play: async ({ canvasElement, args }) => {
    const canvas = within(canvasElement);
    const delayed = canvas.getByRole("button", {
      name: "Inspect ops-02, Delayed, Operations",
    });
    await userEvent.click(delayed);
    await expect(args.onSensor).toHaveBeenCalledWith("SNS-47");
  },
};

export const EngineeringGroup: Story = {
  args: { sensors: sensors.filter((s) => s.group === "Engineering") },
};
export const EmptyScope: Story = { args: { sensors: [] } };
export const ArchiveWithoutFleetHealth: Story = {
  args: {
    sensors: [],
    meta: {
      mode: "live",
      source: "Archive adapter · example state",
      asOf: AS_OF,
    },
  },
};
