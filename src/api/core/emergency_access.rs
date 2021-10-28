use chrono::{Duration, Utc};
use rocket::Route;
use rocket_contrib::json::Json;
use serde_json::Value;

use crate::{
    api::{EmptyResult, JsonResult, JsonUpcase, NumberOrString},
    auth::{decode_emergency_access_invite, Headers},
    db::{models::*, DbConn, DbPool},
    mail, CONFIG,
};

pub fn routes() -> Vec<Route> {
    routes![
        get_contacts,
        get_grantees,
        get_emergency_access,
        put_emergency_access,
        delete_emergency_access,
        post_delete_emergency_access,
        send_invite,
        resend_invite,
        accept_invite,
        confirm_emergency_access,
        initiate_emergency_access,
        approve_emergency_access,
        reject_emergency_access,
        takeover_emergency_access,
        password_emergency_access,
        view_emergency_access,
        policies_emergency_access,
    ]
}

// region get

#[get("/emergency-access/trusted")]
fn get_contacts(headers: Headers, conn: DbConn) -> JsonResult {
    check_emergency_access_allowed()?;

    let ea_list = EmergencyAccess::find_all_by_grantor_uuid(&headers.user.uuid, &conn);

    let ea_list_json: Vec<Value> =
        ea_list.iter().map(|e| e.to_json_grantee_details(&conn)).collect();

    Ok(Json(json!({
      "Data": ea_list_json,
      "Object": "list",
      "ContinuationToken": null
    })))
}

#[get("/emergency-access/granted")]
fn get_grantees(headers: Headers, conn: DbConn) -> JsonResult {
    check_emergency_access_allowed()?;

    let ea_list = EmergencyAccess::find_all_by_grantee_uuid(&headers.user.uuid, &conn);

    let ea_list_json: Vec<Value> =
        ea_list.iter().map(|e| e.to_json_grantor_details(&conn)).collect();

    Ok(Json(json!({
      "Data": ea_list_json,
      "Object": "list",
      "ContinuationToken": null
    })))
}

#[get("/emergency-access/<emer_id>")]
fn get_emergency_access(emer_id: String, conn: DbConn) -> JsonResult {
    check_emergency_access_allowed()?;

    match EmergencyAccess::find_by_uuid(&emer_id, &conn) {
        Some(ea) => Ok(Json(ea.to_json_grantee_details(&conn))),
        _ => err!("Emergency access not valid"),
    }
}

// endregion

// region put/post

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct EmergencyAccessUpdateData {
    Type: NumberOrString,
    WaitTimeDays: i32,
    KeyEncrypted: Option<String>,
}

#[put("/emergency-access/<emer_id>", data = "<data>")]
fn put_emergency_access(emer_id: String, data: JsonUpcase<EmergencyAccessUpdateData>, conn: DbConn) -> JsonResult {
    post_emergency_access(emer_id, data, conn)
}

#[post("/emergency-access/<emer_id>", data = "<data>")]
fn post_emergency_access(emer_id: String, data: JsonUpcase<EmergencyAccessUpdateData>, conn: DbConn) -> JsonResult {
    check_emergency_access_allowed()?;

    let data: EmergencyAccessUpdateData = data.into_inner().data;

    let mut ea = match EmergencyAccess::find_by_uuid(&emer_id, &conn) {
        Some(ea) => ea,
        _ => err!("Emergency access not valid"),
    };

    let new_type = match EmergencyAccessType::from_str(&data.Type.into_string()) {
        Some(new_type) => new_type as i32,
        _ => err!("Invalid emergency access type"),
    };

    ea.atype = new_type;
    ea.wait_time_days = data.WaitTimeDays;
    ea.key_encrypted = data.KeyEncrypted;

    ea.save(&conn)?;
    Ok(Json(ea.to_json()))
}

// endregion

// region delete

#[delete("/emergency-access/<emer_id>")]
fn delete_emergency_access(emer_id: String, headers: Headers, conn: DbConn) -> EmptyResult {
    check_emergency_access_allowed()?;

    let grantor_user = headers.user;

    let ea = match EmergencyAccess::find_by_uuid(&emer_id, &conn) {
        Some(emer) => {
            if emer.grantor_uuid != grantor_user.uuid && emer.grantee_uuid != Some(grantor_user.uuid) {
                err!("Emergency access not valid")
            }
            emer
        }
        _ => err!("Emergency access not valid"),
    };
    ea.delete(&conn)?;
    Ok(())
}

#[post("/emergency-access/<emer_id>/delete")]
fn post_delete_emergency_access(emer_id: String, headers: Headers, conn: DbConn) -> EmptyResult {
    delete_emergency_access(emer_id, headers, conn)
}

// endregion

// region invite

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct EmergencyAccessInviteData {
    Email: String,
    Type: NumberOrString,
    WaitTimeDays: i32,
}

#[post("/emergency-access/invite", data = "<data>")]
fn send_invite(data: JsonUpcase<EmergencyAccessInviteData>, headers: Headers, conn: DbConn) -> EmptyResult {
    check_emergency_access_allowed()?;

    let data: EmergencyAccessInviteData = data.into_inner().data;
    let email = data.Email.to_lowercase();
    let wait_time_days = data.WaitTimeDays;

    let ea_type = match EmergencyAccessType::from_str(&data.Type.into_string()) {
        Some(ea_type) => ea_type as i32,
        _ => err!("Invalid emergency access type"),
    };

    let grantor_user = headers.user;

    // avoid setting yourself as emergency contact
    if email == grantor_user.email {
        err!("You cannot set yourself as an emergency contact")
    }

    let grantee_user = match User::find_by_mail(&email, &conn) {
        Some(user) => user,
        _ => {
            if !CONFIG.signups_allowed() {
                err!(format!("Grantee user does not exist: {}", email))
            }

            if !CONFIG.is_email_domain_allowed(&email) {
                err!("Email domain not eligible for invitations")
            }

            if !CONFIG.mail_enabled() {
                let invitation = Invitation::new(email.clone());
                invitation.save(&conn)?;
            }

            let mut user = User::new(email.clone());
            user.save(&conn)?;
            user
        }
    };

    if EmergencyAccess::find_by_grantor_uuid_and_grantee_uuid_or_email(
        &grantor_user.uuid,
        &grantee_user.uuid,
        &grantee_user.email,
        &conn,
    )
    .is_some()
    {
        err!(format!("Grantee user already invited: {}", email))
    }

    let mut ea = EmergencyAccess::new(
        grantor_user.uuid.clone(),
        Some(grantee_user.email.clone()),
        EmergencyAccessStatus::Invited as i32,
        ea_type,
        wait_time_days,
    );
    ea.save(&conn)?;

    if CONFIG.mail_enabled() {
        mail::send_emergency_access_invite(
            &grantee_user.email,
            &grantee_user.uuid,
            Some(ea.uuid),
            Some(grantor_user.name),
            Some(grantor_user.email),
        )?;
    } else {
        // Automatically mark user as accepted if no email invites
        match User::find_by_mail(&email, &conn) {
            Some(user) => {
                match _accept_invite(&ea.uuid, user.uuid, Some(email), &conn) {
                    Ok(v) => (v),
                    Err(e) => err!(e.to_string()),
                }
            }
            _ => err!("Grantee user not found"),
        }
    }

    Ok(())
}

#[post("/emergency-access/<emer_id>/reinvite")]
fn resend_invite(emer_id: String, headers: Headers, conn: DbConn) -> EmptyResult {
    check_emergency_access_allowed()?;

    let ea = match EmergencyAccess::find_by_uuid(&emer_id, &conn) {
        Some(emer) => emer,
        _ => err!("Emergency access not valid"),
    };

    if ea.grantor_uuid != headers.user.uuid {
        err!("Emergency access not valid");
    }

    if !ea.has_status(EmergencyAccessStatus::Invited) {
        err!("The grantee user is already accepted or confirmed to the organization");
    }

    let email = match ea.email {
        Some(ref email) => email,
        _ => err!("Email not valid"),
    };

    let grantee_user = match User::find_by_mail(&email, &conn) {
        Some(user) => user,
        _ => err!("Grantee user not found"),
    };

    let grantor_user = headers.user;

    if CONFIG.mail_enabled() {
        mail::send_emergency_access_invite(
            &email,
            &grantor_user.uuid,
            Some(ea.uuid),
            Some(grantor_user.name.clone()),
            Some(grantor_user.email),
        )?;
    } else {
        if Invitation::find_by_mail(&email, &conn).is_none() {
            let invitation = Invitation::new(email.clone());
            invitation.save(&conn)?;
        }

        // Automatically mark user as accepted if no email invites
        match _accept_invite(&ea.uuid, grantee_user.uuid, ea.email, &conn) {
            Ok(v) => (v),
            Err(e) => err!(e.to_string()),
        }
    }

    Ok(())
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct AcceptData {
    Token: String,
}

#[post("/emergency-access/<emer_id>/accept", data = "<data>")]
fn accept_invite(emer_id: String, data: JsonUpcase<AcceptData>, conn: DbConn) -> EmptyResult {
    check_emergency_access_allowed()?;

    let data: AcceptData = data.into_inner().data;
    let token = &data.Token;
    let claims = decode_emergency_access_invite(token)?;

    let grantee_user = match User::find_by_mail(&claims.email, &conn) {
        Some(user) => {
            Invitation::take(&claims.email, &conn);
            user
        }
        _ => err!("Invited user not found"),
    };

    let ea = match EmergencyAccess::find_by_uuid(&emer_id, &conn) {
        Some(ea) => ea,
        _ => err!("Emergency access not valid"),
    };

    // get grantor user to send Accepted email
    let grantor_user = match User::find_by_uuid(&ea.grantor_uuid, &conn) {
        Some(user) => user,
        _ => err!("Grantor user not found"),
    };

    // Check claims against the EA record.
    // XXX is this needed?
    match claims.emer_id {
        Some(id) if id == emer_id => (),
        _ => err!("UUID mismatch")
    }
    match claims.grantor_name {
        Some(name) if name == grantor_user.name => (),
        _ => err!("Grantor name mismatch")
    }
    match claims.grantor_email {
        Some(email) if email == grantor_user.email => (),
        _ => err!("Grantor email mismatch")
    }

    match _accept_invite(&emer_id, grantee_user.uuid.clone(), Some(grantee_user.email.clone()), &conn) {
        Ok(v) => (v),
        Err(e) => err!(e.to_string()),
    }

    if CONFIG.mail_enabled() {
        mail::send_emergency_access_invite_accepted(&grantor_user.email, &grantee_user.email)?;
    }

    Ok(())
}

fn _accept_invite(emer_id: &str, grantee_uuid: String, email: Option<String>, conn: &DbConn) -> EmptyResult {
    let mut ea = match EmergencyAccess::find_by_uuid(emer_id, conn) {
        Some(emer) => emer,
        _ => err!("Emergency access not valid"),
    };

    if ea.has_status(EmergencyAccessStatus::Accepted) {
        err!("Emergency contact already accepted");
    }

    let ea_email = ea.email;
    if ea_email.is_none() || ea_email != email {
        err!("User email does not match invite");
    }

    // if let Some(email) = ea.email {
    //     if emailemer_email != email {
    //         err!("User email does not match invite");
    //     }
    // } else {
    //     err!("User email does not match invite");
    // }

    ea.status = EmergencyAccessStatus::Accepted as i32;
    ea.grantee_uuid = Some(grantee_uuid);
    ea.email = None;
    ea.save(conn)
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct ConfirmData {
    Key: String,
}

#[post("/emergency-access/<emer_id>/confirm", data = "<data>")]
fn confirm_emergency_access(
    emer_id: String,
    data: JsonUpcase<ConfirmData>,
    headers: Headers,
    conn: DbConn,
) -> JsonResult {
    check_emergency_access_allowed()?;

    let data: ConfirmData = data.into_inner().data;
    let key = data.Key;
    if key.is_empty() {
        err!("Encrypted key is blank")
    }

    let mut ea = match EmergencyAccess::find_by_uuid(&emer_id, &conn) {
        Some(ea) => ea,
        _ => err!("Emergency access not valid"),
    };

    if !ea.has_status(EmergencyAccessStatus::Accepted) {
        err!("Emergency access not in Accepted state")
    }

    let grantor_uuid = headers.user.uuid;
    if ea.grantor_uuid != grantor_uuid {
        err!("Grantor UUID mismatch")
    }

    let grantor_user = match User::find_by_uuid(&grantor_uuid, &conn) {
        Some(user) => user,
        _ => err!("Grantor user not found"),
    };

    let grantee_uuid = match ea.grantee_uuid {
        Some(ref uuid) => uuid,
        _ => err!("Missing Grantee UUID"),
    };

    let grantee_user = match User::find_by_uuid(grantee_uuid, &conn) {
        Some(user) => user,
        _ => err!("Grantee user not found"),
    };

    ea.status = EmergencyAccessStatus::Confirmed as i32;
    ea.email = None;
    ea.key_encrypted = Some(key);
    ea.save(&conn)?;

    if CONFIG.mail_enabled() {
        mail::send_emergency_access_invite_confirmed(&grantee_user.email, &grantor_user.name)?;
    }

    Ok(Json(ea.to_json()))
}

// endregion

// region access emergency access

#[post("/emergency-access/<emer_id>/initiate")]
fn initiate_emergency_access(emer_id: String, headers: Headers, conn: DbConn) -> JsonResult {
    check_emergency_access_allowed()?;

    let initiating_user = headers.user;
    let mut ea = match EmergencyAccess::find_by_uuid(&emer_id, &conn) {
        Some(emer) => emer,
        _ => err!("Emergency access not valid"),
    };

    if ea.status != EmergencyAccessStatus::Confirmed as i32
        || ea.grantee_uuid != Some(initiating_user.uuid.clone())
    {
        err!("Emergency access not valid")
    }

    let grantor_user = match User::find_by_uuid(&ea.grantor_uuid, &conn) {
        Some(user) => user,
        _ => err!("Grantor user not found"),
    };

    let now = Utc::now().naive_utc();
    ea.status = EmergencyAccessStatus::RecoveryInitiated as i32;
    ea.updated_at = now;
    ea.recovery_initiated_at = Some(now);
    ea.last_notification_at = Some(now);
    ea.save(&conn)?;

    if CONFIG.mail_enabled() {
        mail::send_emergency_access_recovery_initiated(
            &grantor_user.email,
            &initiating_user.name,
            ea.get_type_as_str(),
            &ea.wait_time_days.clone().to_string(),
        )?;
    }
    Ok(Json(ea.to_json()))
}

#[post("/emergency-access/<emer_id>/approve")]
fn approve_emergency_access(emer_id: String, headers: Headers, conn: DbConn) -> JsonResult {
    check_emergency_access_allowed()?;

    let approving_user = headers.user;
    let mut ea = match EmergencyAccess::find_by_uuid(&emer_id, &conn) {
        Some(emer) => emer,
        _ => err!("Emergency access not valid"),
    };

    if !ea.has_status(EmergencyAccessStatus::RecoveryInitiated) {
        err!("Emergency access not in RecoveryInitiated state")
    }

    if ea.grantor_uuid != approving_user.uuid {
        err!("Grantor UUID mismatch")
    }

    let grantor_user = match User::find_by_uuid(&approving_user.uuid, &conn) {
        Some(user) => user,
        _ => err!("Grantor user not found"),
    };

    if let Some(grantee_uuid) = ea.grantee_uuid.as_ref() {
        let grantee_user = match User::find_by_uuid(grantee_uuid, &conn) {
            Some(user) => user,
            _ => err!("Grantee user not found"),
        };

        ea.status = EmergencyAccessStatus::RecoveryApproved as i32;
        ea.save(&conn)?;

        if CONFIG.mail_enabled() {
            mail::send_emergency_access_recovery_approved(&grantee_user.email, &grantor_user.name)?;
        }
        Ok(Json(ea.to_json()))
    } else {
        err!("Grantee user not found")
    }
}

#[post("/emergency-access/<emer_id>/reject")]
fn reject_emergency_access(emer_id: String, headers: Headers, conn: DbConn) -> JsonResult {
    check_emergency_access_allowed()?;

    let rejecting_user = headers.user;
    let mut ea = match EmergencyAccess::find_by_uuid(&emer_id, &conn) {
        Some(emer) => emer,
        _ => err!("Emergency access not valid"),
    };

    if (ea.status != EmergencyAccessStatus::RecoveryInitiated as i32
        && ea.status != EmergencyAccessStatus::RecoveryApproved as i32)
        || ea.grantor_uuid != rejecting_user.uuid
    {
        err!("Emergency access not valid")
    }

    let grantor_user = match User::find_by_uuid(&rejecting_user.uuid, &conn) {
        Some(user) => user,
        _ => err!("Grantor user not found"),
    };

    if let Some(grantee_uuid) = ea.grantee_uuid.as_ref() {
        let grantee_user = match User::find_by_uuid(grantee_uuid, &conn) {
            Some(user) => user,
            _ => err!("Grantee user not found"),
        };

        ea.status = EmergencyAccessStatus::Confirmed as i32;
        ea.key_encrypted = None;
        ea.save(&conn)?;

        if CONFIG.mail_enabled() {
            mail::send_emergency_access_recovery_rejected(&grantee_user.email, &grantor_user.name)?;
        }
        Ok(Json(ea.to_json()))
    } else {
        err!("Grantee user not found")
    }
}

// endregion

// region action

#[post("/emergency-access/<emer_id>/view")]
fn view_emergency_access(emer_id: String, headers: Headers, conn: DbConn) -> JsonResult {
    check_emergency_access_allowed()?;

    let requesting_user = headers.user;
    let host = headers.host;
    let ea = match EmergencyAccess::find_by_uuid(&emer_id, &conn) {
        Some(emer) => emer,
        _ => err!("Emergency access not valid"),
    };

    if !is_valid_request(&ea, requesting_user.uuid, EmergencyAccessType::View) {
        err!("Emergency access not valid")
    }

    let ciphers = Cipher::find_owned_by_user(&ea.grantor_uuid, &conn);

    let ciphers_json: Vec<Value> =
        ciphers.iter().map(|c| c.to_json(&host, &ea.grantor_uuid, &conn)).collect();

    Ok(Json(json!({
      "Ciphers": ciphers_json,
      "KeyEncrypted": &ea.key_encrypted,
      "Object": "emergencyAccessView",
    })))
}

#[post("/emergency-access/<emer_id>/takeover")]
fn takeover_emergency_access(emer_id: String, headers: Headers, conn: DbConn) -> JsonResult {
    check_emergency_access_allowed()?;

    let requesting_user = headers.user;
    let ea = match EmergencyAccess::find_by_uuid(&emer_id, &conn) {
        Some(emer) => emer,
        _ => err!("Emergency access not valid"),
    };

    if !is_valid_request(&ea, requesting_user.uuid, EmergencyAccessType::Takeover) {
        err!("Emergency access not valid")
    }

    let grantor_user = match User::find_by_uuid(&ea.grantor_uuid, &conn) {
        Some(user) => user,
        _ => err!("Grantor user not found"),
    };

    Ok(Json(json!({
      "Kdf": grantor_user.client_kdf_type,
      "KdfIterations": grantor_user.client_kdf_iter,
      "KeyEncrypted": &ea.key_encrypted,
      "Object": "emergencyAccessTakeover",
    })))
}

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct EmergencyAccessPasswordData {
    NewMasterPasswordHash: String,
    Key: String,
}

#[post("/emergency-access/<emer_id>/password", data = "<data>")]
fn password_emergency_access(
    emer_id: String,
    data: JsonUpcase<EmergencyAccessPasswordData>,
    headers: Headers,
    conn: DbConn,
) -> EmptyResult {
    check_emergency_access_allowed()?;

    let data: EmergencyAccessPasswordData = data.into_inner().data;
    let new_master_password_hash = &data.NewMasterPasswordHash;
    let key = data.Key;

    let requesting_user = headers.user;
    let ea = match EmergencyAccess::find_by_uuid(&emer_id, &conn) {
        Some(emer) => emer,
        _ => err!("Emergency access not valid"),
    };

    if !is_valid_request(&ea, requesting_user.uuid, EmergencyAccessType::Takeover) {
        err!("Emergency access not valid")
    }

    let mut grantor_user = match User::find_by_uuid(&ea.grantor_uuid, &conn) {
        Some(user) => user,
        _ => err!("Grantor user not found"),
    };

    // change grantor_user password
    grantor_user.set_password(new_master_password_hash, None);
    grantor_user.akey = key;
    grantor_user.save(&conn)?;

    // Disable TwoFactor providers since they will otherwise block logins
    TwoFactor::delete_all_by_user(&grantor_user.uuid, &conn)?;

    // Removing owner, check that there are at least another owner
    let user_org_grantor = UserOrganization::find_any_state_by_user(&grantor_user.uuid, &conn);

    // Remove grantor from all organisations unless Owner
    for user_org in user_org_grantor {
        if user_org.atype != UserOrgType::Owner as i32 {
            user_org.delete(&conn)?;
        }
    }
    Ok(())
}

// endregion

#[get("/emergency-access/<emer_id>/policies")]
fn policies_emergency_access(emer_id: String, headers: Headers, conn: DbConn) -> JsonResult {
    let requesting_user = headers.user;
    let ea = match EmergencyAccess::find_by_uuid(&emer_id, &conn) {
        Some(emer) => emer,
        _ => err!("Emergency access not valid"),
    };

    if !is_valid_request(&ea, requesting_user.uuid, EmergencyAccessType::Takeover) {
        err!("Emergency access not valid")
    }

    let grantor_user = match User::find_by_uuid(&ea.grantor_uuid, &conn) {
        Some(user) => user,
        _ => err!("Grantor user not found"),
    };

    let policies = OrgPolicy::find_confirmed_by_user(&grantor_user.uuid, &conn);
    let policies_json: Vec<Value> = policies.iter().map(OrgPolicy::to_json).collect();

    Ok(Json(json!({
        "Data": policies_json,
        "Object": "list",
        "ContinuationToken": null
    })))
}

fn is_valid_request(
    ea: &EmergencyAccess,
    requesting_user_uuid: String,
    requested_access_type: EmergencyAccessType,
) -> bool {
    ea.grantee_uuid == Some(requesting_user_uuid)
        && ea.status == EmergencyAccessStatus::RecoveryApproved as i32
        && ea.atype == requested_access_type as i32
}

fn check_emergency_access_allowed() -> EmptyResult {
    if !CONFIG.emergency_access_allowed() {
        err!("Emergency access is not allowed")
    }
    Ok(())
}

pub fn emergency_request_timeout_job(pool: DbPool) {
    debug!("Start emergency_request_timeout_job");
    if !CONFIG.emergency_access_allowed() {
        return;
    }

    let conn = match pool.get() {
        Ok(conn) => conn,
        _ => {
            error!("Failed to get DB connection in emergency_request_timeout_job()");
            return;
        }
    };

    let ea_list = EmergencyAccess::find_all_recoveries(&conn);

    if ea_list.is_empty() {
        debug!("No emergency access requests to consider granting");
    }

    let now = Utc::now().naive_utc();
    for mut emer in ea_list {
        if let Some(t) = emer.recovery_initiated_at {
            if t + Duration::days(emer.wait_time_days as i64) < now {
                continue; // Request hasn't met the wait time requirement.
            }

            emer.status = EmergencyAccessStatus::RecoveryApproved as i32;
            emer.save(&conn).expect("Cannot save emergency access on job");

            if CONFIG.mail_enabled() {
                let grantor_user = User::find_by_uuid(&emer.grantor_uuid, &conn).expect("Grantor user not found");
                let grantee_uuid = emer.grantee_uuid.as_ref().expect("Grantee user invalid");
                let grantee_user = User::find_by_uuid(grantee_uuid, &conn).expect("Grantee user not found");

                mail::send_emergency_access_recovery_timed_out(
                    &grantor_user.email,
                    &grantee_user.name,
                    emer.get_type_as_str(),
                )
                .expect("Error sending email to grantor");

                mail::send_emergency_access_recovery_approved(&grantee_user.email, &grantor_user.name)
                    .expect("Error sending email to grantee");
            }
        }
    }
}

pub fn emergency_notification_reminder_job(pool: DbPool) {
    debug!("Start emergency_notification_reminder_job");
    if !CONFIG.emergency_access_allowed() || !CONFIG.mail_enabled() {
        return;
    }

    let conn = match pool.get() {
        Ok(conn) => conn,
        _ => {
            error!("Failed to get DB connection in emergency_notification_reminder_job()");
            return;
        }
    };

    let ea_list = EmergencyAccess::find_all_recoveries(&conn);

    if ea_list.is_empty() {
        debug!("No emergency access requests to send reminders for");
    }

    let now = Utc::now().naive_utc();
    for mut emer in ea_list {

        // if (emer.recovery_initiated_at.is_some()
        //         && Utc::now().naive_utc()
        //             >= emer.recovery_initiated_at.unwrap() + Duration::days((emer.wait_time_days as i64) - 1))
        //         && (emer.last_notification_at.is_none()
        //             || (emer.last_notification_at.is_some()
        //                 && Utc::now().naive_utc() >= emer.last_notification_at.unwrap() + Duration::days(1)))

        // we are within one day of the wait time being met
        // now >= recovery_initiated_at + wait-1

        if emer.recovery_initiated_at.is_none() {
            error!("Reoovery initiated, but no value for recovery_initiated_at");
            continue;
        }
        let recovery_initiated_at = emer.recovery_initiated_at.unwrap();
        if recovery_initiated_at + Duration::days((emer.wait_time_days as i64) - 1) < now {
            // There's less than one day before the wait time is met, so no need to send a reminder.
            continue;
        }

        if let Some(last_notification_at) = emer.last_notification_at {
            if last_notification_at + Duration::days(1) < now {
                // Don't send a reminder if one has been sent within the last day.
                continue;
            }
        }

        emer.last_notification_at = Some(now);
        emer.save(&conn).expect("Failed to update last_notification_at");

        let grantor_user = User::find_by_uuid(&emer.grantor_uuid, &conn).expect("Grantor user not found");
        let grantee_uuid = emer.grantee_uuid.as_ref().expect("Grantee user invalid");
        let grantee_user = User::find_by_uuid(grantee_uuid, &conn).expect("Grantee user not found");

        let remaining_time = now - recovery_initiated_at;
        let remaining_days = remaining_time.num_days() as i32;
        // DaysLeft = emergencyAccess.WaitTimeDays - Convert.ToInt32((remainingTime).TotalDays)
        let days_left = (emer.wait_time_days - remaining_days).to_string();

        mail::send_emergency_access_recovery_reminder(
            &grantor_user.email,
            &grantee_user.name,
            emer.get_type_as_str(),
            &days_left,
        ).expect("Error sending email");
    }
}
