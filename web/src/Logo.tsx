export function Logo({ size = 36 }: { size?: number }) {
  return (
    <img
      src="/heimdall.svg"
      alt=""
      aria-hidden="true"
      width={size}
      height={size}
    />
  );
}
