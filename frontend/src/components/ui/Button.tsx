import { Slot } from '@radix-ui/react-slot'
import { cva } from 'class-variance-authority'
import type { VariantProps } from 'class-variance-authority'
import type { ComponentProps } from 'react'

// Source-owned shadcn/ui composition adapted to the SecureVault theme.
const variants = cva('sv-button', {
  variants: { variant: { default: 'primary', outline: 'secondary', icon: 'icon-button' } },
  defaultVariants: { variant: 'default' },
})

type Props = ComponentProps<'button'> & VariantProps<typeof variants> & { asChild?: boolean }

export function Button({ asChild = false, variant, className, ...attributes }: Props) {
  const Root = asChild ? Slot : 'button'
  return <Root className={variants({ variant, className })} data-slot="button" {...attributes} />
}
