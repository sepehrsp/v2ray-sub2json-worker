<!-- src/lib/components/Button.svelte -->
<script lang="ts">
	import type { Snippet } from 'svelte';

	let {
		type = 'button',
		className = '',
		ariaLabel = '',
		onClick = () => {},
		children
	}: {
		type?: 'button' | 'submit' | 'reset';
		className?: string;
		ariaLabel?: string;
		onClick?: () => void;
		children: Snippet;
	} = $props();
</script>

<button {type} class="button {className}" aria-label={ariaLabel} onclick={onClick}>
	{@render children()}
</button>

<style>
	.button {
		padding: 0.75rem 1rem;
		border: none;
		border-radius: 8px;
		font-size: 1rem;
		cursor: pointer;
		transition:
			background-color 0.3s,
			transform 0.2s;
		display: flex;
		align-items: center;
		gap: 0.5rem;
	}
	.button:hover {
		transform: translateY(-2px);
	}
</style>
