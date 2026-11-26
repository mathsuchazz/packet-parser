//! Wireshark-style text formatting for [`IcmpMessage`].

use crate::{
    hexdump::Hexdump,
    layer3::icmp::{IcmpBody, IcmpMessage},
};
use std::fmt;

impl<'a> fmt::Display for IcmpMessage<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Internet Control Message Protocol")?;

        writeln!(f, "Type: {} ({})", self.type_, self.type_.value())?;

        writeln!(f, "Code: {}", self.code)?;

        writeln!(
            f,
            "Checksum: {:#06x} [{}]",
            self.checksum_, self.checksum_status
        )?;
        self.checksum_status.write_status(f, "Checksum")?;

        match self.body {
            IcmpBody::Echo(Some(echo)) => {
                writeln!(
                    f,
                    "Identifier: {} ({:#06x})",
                    echo.identifier, echo.identifier
                )?;

                writeln!(
                    f,
                    "Sequence Number: {} ({:#06x})",
                    echo.sequence_number, echo.sequence_number
                )?;

                Self::write_data(f, echo.data)?;
            }
            IcmpBody::Echo(None) => {}
            IcmpBody::Other(raw_body) => Self::write_data(f, raw_body)?,
        }

        self.write_anomalies(f)
    }
}

impl<'a> IcmpMessage<'a> {
    fn write_anomalies(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for anomaly in &self.anomalies {
            writeln!(f, "[Expert Info: {anomaly}]")?;
        }
        Ok(())
    }

    fn write_data(f: &mut fmt::Formatter<'_>, data: &[u8]) -> fmt::Result {
        writeln!(f, "Data ({} bytes)", data.len())?;
        write!(f, "{}", Hexdump(data))
    }
}
