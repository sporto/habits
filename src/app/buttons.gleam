import app/icons
import gleam/list
import gleam/option.{type Option, None, Some}
import lustre/attribute.{class} as attr
import lustre/element.{text}
import lustre/element/html
import lustre/event

pub type Action(msg) {
  ActionNone
  ActionClick(msg)
  ActionSubmit
  ActionLink(String)
}

pub type Variant {
  VariantPrimary
  VariantDanger
  VariantSecondary
  VariantOutlined
  VariantUnfilled
}

pub type Config(msg) {
  Config(
    action: Action(msg),
    attrs: List(attr.Attribute(msg)),
    icon_left: Option(icons.Icon),
    icon_right: Option(icons.Icon),
    is_active: Bool,
    is_disabled: Bool,
    label: Option(String),
    variant: Variant,
  )
}

pub fn new(action action: Action(msg)) {
  Config(
    action: action,
    attrs: [],
    icon_left: None,
    icon_right: None,
    is_active: False,
    is_disabled: False,
    label: None,
    variant: VariantPrimary,
  )
}

pub fn with_action(config, action) {
  Config(..config, action: action)
}

pub fn with_attrs(config, attrs) {
  Config(..config, attrs: attrs)
}

pub fn with_icon_left(config, icon_left) {
  Config(..config, icon_left: Some(icon_left))
}

pub fn with_is_active(config, is_active) {
  Config(..config, is_active: is_active)
}

pub fn with_is_disabled(config, is_disabled) {
  Config(..config, is_disabled: is_disabled)
}

pub fn with_label(config, label) {
  Config(..config, label: Some(label))
}

pub fn with_variant(config, variant) {
  Config(..config, variant: variant)
}

pub fn button_primary(action action: Action(msg), label label: String) {
  new(action)
  |> with_label(label)
}

pub fn button_secondary(action action: Action(msg), label label: String) {
  new(action)
  |> with_label(label)
  |> with_variant(VariantSecondary)
}

pub fn button_danger(action action: Action(msg), label label: String) {
  new(action)
  |> with_label(label)
  |> with_variant(VariantDanger)
}

/// A link that looks like a button
pub fn link_button(href href: String, label label: String) {
  new(ActionLink(href))
  |> with_label(label)
}

pub fn icon(action action: Action(msg), icon icon_: icons.Icon) {
  new(action)
  |> with_icon_left(icon_)
  |> with_variant(VariantSecondary)
}

pub fn icon_danger(action action: Action(msg), icon icon_: icons.Icon) {
  new(action)
  |> with_icon_left(icon_)
  |> with_variant(VariantDanger)
}

const classes_button_base = "focus:ring-4 font-medium py-2.5 h-12 rounded-sm text-sm focus:outline-none cursor-pointer inline-flex items-center"

const classes_button_primary = "bg-blue-700 hover:bg-blue-800 focus:ring-blue-300 text-white"

const classes_button_secondary = "bg-gray-700 hover:bg-gray-800 focus:ring-gray-300 text-white"

const classes_button_outlined_base = "focus:ring-gray-300 border border-slate-500"

const classes_button_outlined_inactive = "text-gray600"

const classes_button_outlined_active = "bg-gray-700 text-white"

const classes_button_danger = "bg-red-700 hover:bg-red-800 focus:ring-red-300 text-white"

type Classes {
  Classes(base: String, active: String, inactive: String)
}

fn classes_for_variant(variant: Variant) -> Classes {
  case variant {
    VariantPrimary -> Classes(classes_button_primary, "", "")
    VariantDanger -> Classes(classes_button_danger, "", "")
    VariantSecondary -> Classes(classes_button_secondary, "", "")
    VariantOutlined ->
      Classes(
        base: classes_button_outlined_base,
        active: classes_button_outlined_active,
        inactive: classes_button_outlined_inactive,
      )
    VariantUnfilled -> Classes("", "", "")
  }
}

fn classes_for(variant: Variant, is_active: Bool) {
  let classes = classes_for_variant(variant)

  [
    #(classes.base, True),
    #(classes.active, is_active),
    #(classes.inactive, !is_active),
  ]
}

pub fn view(config: Config(a)) {
  let classes =
    attr.classes([
      #("t-button", True),
      #("-is-active", config.is_active),
      #(classes_button_base, True),
      ..classes_for(config.variant, config.is_active)
    ])

  let icon_left = case config.icon_left {
    Some(icon) -> [html.span([class("px-2")], [make_icon(icon)])]
    None -> []
  }

  let icon_right = case config.icon_right {
    Some(icon) -> [html.span([class("px-2")], [make_icon(icon)])]
    None -> []
  }

  let label = case config.label {
    Some(label) -> [
      html.span(
        [
          attr.classes([
            #("pl-3", config.icon_left == None),
            #("pr-3", config.icon_right == None),
          ]),
        ],
        [text(label)],
      ),
    ]
    None -> []
  }

  let content = list.concat([icon_left, label, icon_right])

  case config.action {
    ActionNone | ActionClick(_) | ActionSubmit -> {
      let maybe_submit = case config.action {
        ActionSubmit -> attr.type_("submit")
        _ -> attr.none()
      }
      let maybe_click = case config.action {
        ActionClick(msg) -> event.on_click(msg)
        _ -> attr.none()
      }
      html.button(
        [
          classes,
          maybe_submit,
          maybe_click,
          attr.disabled(config.is_disabled),
          ..config.attrs
        ],
        content,
      )
    }
    ActionLink(href) -> {
      html.a([classes, attr.href(href), ..config.attrs], content)
    }
  }
}

/// Traditional Rails like form in a button, which can do a POST
pub fn button_form(label label: String, url url: String) {
  html.form([attr.method("post"), attr.action(url)], [
    html.input([
      attr.type_("submit"),
      class(classes_button_base),
      class(classes_button_danger),
      attr.value(label),
    ]),
  ])
}

pub fn make_icon(icon icon: icons.Icon) {
  icons.icon(icon)
}
