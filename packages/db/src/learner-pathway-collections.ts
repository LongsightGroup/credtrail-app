/** Groups values by a derived key while preserving input order within each group. */
export const groupLearnerPathwayValues = <Key, Value>(
  values: readonly Value[],
  keyForValue: (value: Value) => Key,
): Map<Key, Value[]> => {
  const groups = new Map<Key, Value[]>();

  for (const value of values) {
    const key = keyForValue(value);
    const group = groups.get(key);

    if (group === undefined) {
      groups.set(key, [value]);
    } else {
      group.push(value);
    }
  }

  return groups;
};
