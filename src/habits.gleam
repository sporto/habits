import gleam/dynamic
import gleam/int
import gleam/json
import gleam/list
import lustre
import lustre/attribute as attr
import lustre/effect
import lustre/element
import lustre/element/html.{div, text}
import lustre/event
import lustre_http

pub type Flags {
  Flags(api_url: String)
}

pub type Model {
  Model(login_form: LoginForm, flags: Flags)
}

fn new_model() -> Model {
  Model(
    flags: Flags(api_url: "https://123.supabase.co"),
    login_form: new_login_form(),
  )
}

pub type LoginForm {
  LoginForm(email: String, password: String)
}

pub fn new_login_form() -> LoginForm {
  LoginForm(email: "", password: "")
}

fn init(_flags) -> #(Model, effect.Effect(Msg)) {
  #(new_model(), effect.none())
}

pub type Msg {
  ApiReturnedLoginResponse(Result(String, lustre_http.HttpError))
  ClickedLogin
  ChangedEmail(String)
  ChangedPassword(String)
}

pub fn main() {
  let app = lustre.application(init, update, view)
  let assert Ok(_) = lustre.start(app, "#app", Nil)

  Nil
}

pub fn update(model: Model, msg: Msg) -> #(Model, effect.Effect(Msg)) {
  case msg {
    ApiReturnedLoginResponse(_) -> #(model, effect.none())
    ChangedEmail(email) -> #(
      Model(..model, login_form: LoginForm(..model.login_form, email: email)),
      effect.none(),
    )
    ChangedPassword(password) -> #(
      Model(
        ..model,
        login_form: LoginForm(..model.login_form, password: password),
      ),
      effect.none(),
    )
    ClickedLogin -> #(model, effect.none())
  }
}

fn login(model: Model) -> effect.Effect(Msg) {
  let decoder = dynamic.field("_id", dynamic.string)
  let expect = lustre_http.expect_json(decoder, ApiReturnedLoginResponse)

  let payload =
    json.object([
      #("email", json.string(model.login_form.email)),
      #("password", json.string(model.login_form.password)),
    ])

  lustre_http.post(model.flags.api_url <> "/auth/v1/login", payload, expect)
}

/// Decoders
pub type LoginResponse {
  LoginResponse(
    access_token: String,
    refresh_token: String,
    expires_at: Int,
    user: LoginUser,
  )
}

pub type LoginUser {
  LoginUser(id: String, email: String)
}

pub fn login_response_decoder() {
  dynamic.decode4(
    LoginResponse,
    dynamic.field("access_token", dynamic.string),
    dynamic.field("refresh_token", dynamic.string),
    dynamic.field("expires_at", dynamic.int),
    dynamic.field("user", login_user_decoder()),
  )
}

pub fn login_user_decoder() {
  dynamic.decode2(
    LoginUser,
    dynamic.field("id", dynamic.string),
    dynamic.field("email", dynamic.string),
  )
}

/// Views
pub fn view(model: Model) -> element.Element(Msg) {
  html.div([], [view_login(model)])
}

fn view_login(model: Model) {
  html.form([event.on_submit(ClickedLogin)], [
    div([], [
      html.label([], [text("Email")]),
      html.input([attr.type_("text"), attr.value(model.login_form.email)]),
    ]),
    div([], [
      html.label([], [text("Passsword")]),
      html.input([attr.type_("password"), attr.value(model.login_form.password)]),
    ]),
    div([], [html.input([attr.type_("submit"), attr.value("Login")])]),
  ])
}
