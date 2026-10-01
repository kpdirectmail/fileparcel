// @ts-check
/**
 * Component barrel — import everything from one place:
 *   import { button, dialog, toast, pageHeader, emptyState } from '../components/index.js';
 *
 * Frozen public API (§13.3). Return types:
 *   → Element:  button, iconButton, pageHeader, breadcrumbs, card, statTile, badge, emptyState, copyField, qrImage,
 *               skeleton, spinner, loadingBlock, settingsForm
 *   → object:   field/select/toggle/checkbox → {el, input, setError, value, name}; form → {el, reset, controls, setError,
 *               submit, values}; dialog → {el, body, actions, open, close, setTitle}; sheet → {el, body, open, close};
 *               menu → {el, close}; tabs → {el, setActive, active}; table → {el, setRows, getSelected, getSelectedRows,
 *               clearSelection, setSort}; virtualList → {el, setCount, refresh, scrollToIndex, nodeAt, destroy};
 *               progress → {el, set}
 *   → Promise:  confirm → boolean, prompt → string|null, promptElevation → boolean
 *   → function: contextMenu → detach
 *   → void:     placeholder(root, opts) ("Coming soon" page body); notFoundPage is a page module
 * Overlays (menu, toast) attach to the top-most open modal <dialog> (core/dom.js overlayHost()), never blindly to
 * <body>, because everything outside a modal is inert.
 * @module components
 */
export { button, iconButton, setBusy } from './button.js';
export { field, select, toggle, checkbox } from './field.js';
export { form } from './form.js';
export { dialog, confirm, prompt } from './dialog.js';
export { promptElevation } from './elevation.js';
export { toast } from './toast.js';
export { menu, contextMenu } from './menu.js';
export { sheet, sheetList } from './sheet.js';
export { tabs } from './tabs.js';
export { table } from './table.js';
export { virtualList } from './virtual-list.js';
export { pageHeader, breadcrumbs } from './page-header.js';
export { card, statTile } from './card.js';
export { badge } from './badge.js';
export { emptyState } from './empty-state.js';
export { copyField, copyText } from './copy-field.js';
export { qrImage, qrURL } from './qr-image.js';
export { progress, skeleton, spinner, loadingBlock } from './progress.js';
export { settingsForm } from './settings-form.js';
export { openPalette, showShortcuts } from './palette.js';
export { placeholder, notFoundPage } from './placeholder.js';
