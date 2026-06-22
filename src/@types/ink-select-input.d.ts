declare module 'ink-select-input' {
  import { FC } from 'react';
  interface SelectInputProps {
    items: Array<{ label: string; value: string | number }>;
    onSelect: (item: { label: string; value: string | number }) => void;
  }
  const SelectInput: FC<SelectInputProps>;
  export default SelectInput;
}
