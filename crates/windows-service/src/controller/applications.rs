use super::*;
use crate::{ApplicationRouteRequest, application_plan};
use sirinvpn_tunnel_model::TunnelRoutingMode;

impl Controller {
    pub(super) fn application_driver_ready(&self) -> bool {
        crate::application_driver::running() && self.firewall.application_driver_registered()
    }
    pub(super) async fn route_application(
        &mut self,
        request: ApplicationRouteRequest,
    ) -> Result<(), ServiceError> {
        self.expect_server(request.server_id)?;
        if !self.application_driver_ready() {
            return Err(ServiceError::ApplicationDriverUnavailable);
        }
        if self.enforcement_failed
            || !self.firewall.verified().map_err(network_error)?
            || self.active.as_ref().is_none_or(|active| {
                active.connected_at.is_none()
                    || active.request.routing.mode != TunnelRoutingMode::SelectedApplications
            })
            || self
                .saved
                .as_ref()
                .is_none_or(|saved| saved.phase != SessionPhase::Active)
        {
            return Err(ServiceError::SessionChanged);
        }
        let application = application_plan::select(&request.executable)?;
        let saved = self.saved.as_mut().ok_or(ServiceError::SessionChanged)?;
        if !saved
            .applications
            .iter()
            .any(|selected| selected.app_id == application.app_id)
        {
            if saved.applications.len() >= application_plan::MAX_APPLICATIONS {
                return Err(ServiceError::ApplicationLimit);
            }
            saved.schema_version = 2;
            saved.applications.push(application);
            // A crash after this commit closes the new application's guard on
            // restart. The desktop receives no launch acknowledgement yet.
            if let Err(error) = self.persist() {
                self.saved.as_mut().unwrap().applications.pop();
                return Err(network_error(error));
            }
        }
        if self
            .firewall
            .apply(self.plan().ok_or(ServiceError::SessionChanged)?)
            .is_err()
        {
            self.enforcement_failed = true;
            let _ = self.hold().await;
            return Err(ServiceError::NetworkOperation);
        }
        Ok(())
    }
}
