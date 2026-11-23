import { useState } from "react";
import type { InputHTMLAttributes } from "react";

export function parseCommaList(text: string): string[] {
  return text.split(",").map((s) => s.trim()).filter(Boolean);
}

interface Props extends Omit<InputHTMLAttributes<HTMLInputElement>, "value" | "onChange"> {
  value: string[];
  onChange: (list: string[]) => void;
}

// CommaListInput edits a string list as comma-separated text. It keeps what
// was typed, so a trailing comma survives until the next item is entered, and
// falls back to the list whenever the list changes from outside.
export default function CommaListInput({ value, onChange, ...rest }: Props) {
  const [raw, setRaw] = useState(value.join(", "));
  const parsed = parseCommaList(raw);
  const inSync = parsed.length === value.length && parsed.every((s, i) => s === value[i]);
  return (
    <input
      {...rest}
      value={inSync ? raw : value.join(", ")}
      onChange={(e) => {
        setRaw(e.target.value);
        onChange(parseCommaList(e.target.value));
      }}
    />
  );
}
