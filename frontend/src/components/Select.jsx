import { useEffect, useId, useLayoutEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { Check, ChevronDown } from "lucide-react";
import "./Select.css";

function menuPosition(trigger, options, minimumWidth) {
  const rect = trigger.getBoundingClientRect();
  const inset = 12;
  const gap = 8;
  const below = Math.max(0, window.innerHeight - rect.bottom - gap - inset);
  const above = Math.max(0, rect.top - gap - inset);
  const estimatedHeight =
    46 +
    options.reduce(
      (height, option) => height + (option.description ? 74 : 48),
      0,
    );
  const opensAbove = below < Math.min(estimatedHeight, 260) && above > below;
  const height = Math.min(estimatedHeight, 390, opensAbove ? above : below);
  const width = Math.min(
    Math.max(rect.width, minimumWidth),
    window.innerWidth - inset * 2,
  );
  return {
    width,
    maxHeight: height,
    left: Math.max(
      inset,
      Math.min(rect.right - width, window.innerWidth - width - inset),
    ),
    ...(opensAbove
      ? { bottom: window.innerHeight - rect.top + gap }
      : { top: rect.bottom + gap }),
  };
}

/** A select-only combobox. Focus stays on its trigger while navigating options. */
export function Select({
  label,
  value,
  onChange,
  options,
  placeholder = "Select an option",
  disabled = false,
  className = "",
  menuWidth = 260,
}) {
  const id = useId();
  const triggerRef = useRef(null);
  const menuRef = useRef(null);
  const listRef = useRef(null);
  const typeahead = useRef({ text: "", time: 0 });
  const [position, setPosition] = useState(null);
  const [activeIndex, setActiveIndex] = useState(0);
  const open = position !== null;
  const selectedIndex = options.findIndex((option) => option.value === value);
  const selected = options[selectedIndex];
  const highlightedIndex = Math.min(activeIndex, options.length - 1);
  const inactive = disabled || !options.length;
  const listId = `${id}-options`;

  const show = (index = Math.max(0, selectedIndex)) => {
    if (inactive) return;
    setActiveIndex(index);
    setPosition(menuPosition(triggerRef.current, options, menuWidth));
  };
  const choose = (index) => {
    const option = options[index];
    if (!option) return;
    onChange(option.value);
    setPosition(null);
    typeahead.current = { text: "", time: 0 };
    triggerRef.current?.focus({ preventScroll: true });
  };

  useEffect(() => {
    if (!open) return;
    const dismiss = (event) => {
      if (
        !triggerRef.current?.contains(event.target) &&
        !menuRef.current?.contains(event.target)
      )
        setPosition(null);
    };
    const reposition = (event) => {
      // Scrolling the option list should not move or close its own menu.
      if (menuRef.current?.contains(event.target)) return;
      const trigger = triggerRef.current;
      if (!trigger) return;
      const rect = trigger.getBoundingClientRect();
      if (rect.bottom <= 0 || rect.top >= window.innerHeight) setPosition(null);
      else setPosition(menuPosition(trigger, options, menuWidth));
    };
    document.addEventListener("pointerdown", dismiss);
    window.addEventListener("resize", reposition);
    window.addEventListener("scroll", reposition, true);
    return () => {
      document.removeEventListener("pointerdown", dismiss);
      window.removeEventListener("resize", reposition);
      window.removeEventListener("scroll", reposition, true);
    };
  }, [open, options, menuWidth]);

  useLayoutEffect(() => {
    if (!open) return;
    const list = listRef.current;
    const option = list?.children[highlightedIndex];
    if (!option) return;
    // Move only the options viewport, never the assessment page behind it.
    if (option.offsetTop < list.scrollTop) list.scrollTop = option.offsetTop;
    else if (
      option.offsetTop + option.offsetHeight >
      list.scrollTop + list.clientHeight
    ) {
      list.scrollTop =
        option.offsetTop + option.offsetHeight - list.clientHeight;
    }
  }, [open, highlightedIndex]);

  const onKeyDown = (event) => {
    if (inactive) return;
    const { key } = event;
    if (
      ["ArrowDown", "ArrowUp", "Home", "End", "PageDown", "PageUp"].includes(
        key,
      )
    ) {
      event.preventDefault();
      typeahead.current = { text: "", time: 0 };
      let next = open ? highlightedIndex : Math.max(0, selectedIndex);
      if (key === "Home") next = 0;
      else if (key === "End") next = options.length - 1;
      else if (open) {
        const step =
          key === "PageDown"
            ? 5
            : key === "PageUp"
              ? -5
              : key === "ArrowDown"
                ? 1
                : -1;
        next = Math.max(0, Math.min(options.length - 1, next + step));
      }
      if (open) setActiveIndex(next);
      else show(next);
    } else if (
      key === "Enter" ||
      (key === " " &&
        (!typeahead.current.text ||
          performance.now() - typeahead.current.time >= 700))
    ) {
      event.preventDefault();
      if (open) choose(highlightedIndex);
      else show();
    } else if (key === "Escape" && open) {
      event.preventDefault();
      event.stopPropagation();
      setPosition(null);
      typeahead.current = { text: "", time: 0 };
    } else if (key === "Tab") {
      setPosition(null);
      typeahead.current = { text: "", time: 0 };
    } else if (
      key.length === 1 &&
      !event.ctrlKey &&
      !event.metaKey &&
      !event.altKey
    ) {
      event.preventDefault();
      const time = performance.now();
      const text =
        (time - typeahead.current.time < 700 ? typeahead.current.text : "") +
        key.toLowerCase();
      typeahead.current = { text, time };
      const search = [...text].every((character) => character === text[0])
        ? text[0]
        : text;
      const start = open ? highlightedIndex : selectedIndex;
      const index = Array.from(
        { length: options.length },
        (_, offset) => (start + offset + 1) % options.length,
      ).find((index) => options[index].label.toLowerCase().startsWith(search));
      if (index !== undefined) {
        if (open) setActiveIndex(index);
        else show(index);
      }
    }
  };

  return (
    <div className={`custom-select ${className}`}>
      <button
        ref={triggerRef}
        type="button"
        role="combobox"
        className={`select-trigger ${open ? "is-open" : ""}`}
        aria-label={label}
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-controls={open ? listId : undefined}
        aria-activedescendant={
          open && highlightedIndex >= 0
            ? `${id}-option-${highlightedIndex}`
            : undefined
        }
        disabled={inactive}
        onClick={() => {
          typeahead.current = { text: "", time: 0 };
          if (open) setPosition(null);
          else show();
        }}
        onKeyDown={onKeyDown}
        onBlur={() => {
          setPosition(null);
          typeahead.current = { text: "", time: 0 };
        }}
      >
        <span className="select-value">
          <span>{selected?.label || placeholder}</span>
          {selected?.description && <small>{selected.description}</small>}
        </span>
        <ChevronDown size={17} aria-hidden="true" />
      </button>
      {open &&
        createPortal(
          <div ref={menuRef} className="select-popover" style={position}>
            <div className="select-menu-label" aria-hidden="true">
              {label}
              <span>
                {options.length} {options.length === 1 ? "option" : "options"}
              </span>
            </div>
            <ul
              ref={listRef}
              id={listId}
              role="listbox"
              aria-label={label}
              className="select-options"
            >
              {options.map((option, index) => (
                <li
                  key={option.value}
                  id={`${id}-option-${index}`}
                  role="option"
                  aria-selected={option.value === value}
                  className={`select-option ${index === highlightedIndex ? "is-active" : ""} ${option.value === value ? "is-selected" : ""}`}
                  onPointerMove={() => {
                    if (index !== highlightedIndex) setActiveIndex(index);
                  }}
                  onMouseDown={(event) => event.preventDefault()}
                  onClick={() => choose(index)}
                >
                  <span className="select-option-copy">
                    <span>{option.label}</span>
                    {option.description && <small>{option.description}</small>}
                  </span>
                  {option.value === value && (
                    <Check size={17} aria-hidden="true" />
                  )}
                </li>
              ))}
            </ul>
          </div>,
          document.body,
        )}
    </div>
  );
}
