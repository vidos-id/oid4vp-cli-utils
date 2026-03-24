import { z } from "zod";

export const outputFormatSchema = z.enum(["json", "raw"]);
export const jsonOutputFormatSchema = z.enum(["json"]);
