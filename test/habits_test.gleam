import gleam/io
import gleam/json
import gleeunit
import gleeunit/should
import habits
import simplifile

pub fn main() {
  gleeunit.main()
}

fn get_json_fixture(name: String) {
  let filepath = "./test/fixtures/" <> name
  let assert Ok(content) = simplifile.read(from: filepath)
  content
}

// gleeunit test functions end in `_test`
pub fn hello_world_test() {
  1
  |> should.equal(1)
}

pub fn parse_auth_data_test() {
  let json_string = get_json_fixture("login-response.json")
  let data = json.decode(from: json_string, using: habits.auth_data_decoder())

  data |> should.be_ok()
}
