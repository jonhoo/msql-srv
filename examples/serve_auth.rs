//! After running this, you should be able to run:
//!
//! ```console
//! $ echo "SELECT * FROM foo" | mysql -h 127.0.0.1 --table
//! $
//! ```

extern crate msql_srv;
extern crate mysql;
extern crate mysql_common as myc;

use msql_srv::*;
use std::io;
use std::net;
use std::thread;

struct Backend;
impl<W: io::Write> MysqlShim<W> for Backend {
    type Error = io::Error;

    fn on_prepare(&mut self, _: &str, info: StatementMetaWriter<W>) -> io::Result<()> {
        info.reply(42, &[], &[])
    }
    fn on_execute(
        &mut self,
        _: u32,
        _: msql_srv::ParamParser,
        results: QueryResultWriter<W>,
    ) -> io::Result<()> {
        results.completed(0, 0)
    }
    fn on_close(&mut self, _: u32) {}

    fn on_query(&mut self, sql: &str, results: QueryResultWriter<W>) -> io::Result<()> {
        println!("execute sql {:?}", sql);
        results.start(&[])?.finish()
    }

    /// authenticate method for the specified plugin
    fn authenticate(
        &self,
        auth_plugin: &str,
        username: &[u8],
        salt: &[u8],
        auth_data: &[u8],
    ) -> bool {
        println!(
            "auth_plugin, {:?},  user: {:?} ,  salt: {:?}, auth_data:{:?}",
            auth_plugin, username, salt, auth_data
        );

        username == "default".as_bytes()
    }

    fn on_init(&mut self, _: &str, _: InitWriter<'_, W>) -> Result<(), Self::Error> {
        Ok(())
    }

    fn version(&self) -> &str {
        // 5.1.10 because that's what Ruby's ActiveRecord requires
        "5.1.10-alpha-msql-proxy"
    }

    fn connect_id(&self) -> u32 {
        u32::from_le_bytes([0x08, 0x00, 0x00, 0x00])
    }

    fn default_auth_plugin(&self) -> &str {
        "mysql_native_password"
    }

    fn auth_plugin_for_username(&self, _user: &[u8]) -> &str {
        "mysql_native_password"
    }

    fn salt(&self) -> [u8; 20] {
        let bs = ";X,po_k}>o6^Wz!/kM}N".as_bytes();
        let mut scramble: [u8; 20] = [0; 20];
        for i in 0..20 {
            scramble[i] = bs[i];
            if scramble[i] == b'\0' || scramble[i] == b'$' {
                scramble[i] = scramble[i] + 1;
            }
        }
        scramble
    }
}

fn main() {
    let mut threads = Vec::new();
    let listener = net::TcpListener::bind("127.0.0.1:3306").unwrap();

    while let Ok((s, _)) = listener.accept() {
        println!("{:?}", "got one socket");
        threads.push(thread::spawn(move || {
            MysqlIntermediary::run_on_tcp(Backend, s).unwrap();
        }));
    }

    for t in threads {
        t.join().unwrap();
    }
}

#[test]
fn it_works() {
    let c: u8 = b'\0';
    let d: u8 = 0 as u8;
    let e: u8 = 0x00;

    assert_eq!(c, d);
    assert_eq!(e, d);
}
