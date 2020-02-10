# based on original work by Mike Peachey @ BJSS
# modified into ZSH plugin and a few tweeks made by Ian P. Christian @ BJSS
# please feedback modifications to this ZSH plugin to <ian.christian@bjss.com>


# prompt requires p9k or p10k
# in ~/.zshrc
#
#   plugins=(zsh-aws)
#
# in ~/.p10k.zsh
#
# typeset -ga POWERLEVEL9K_LEFT_PROMPT_ELEMENTS=(
# ....
# aws_prompt_info
# ....
# )
#

function aws_unset_creds() {
  echo "Unsetting all existing AWS_* credential-related environment variables...";
  unset AWS_ACCESS_KEY_ID;
  unset AWS_SECRET_ACCESS_KEY;
  unset AWS_SESSION_TOKEN;
  unset AWS_MFA_EXPIRY;
  unset AWS_SESSION_EXPIRY;
  unset AWS_ROLE;
  unset AWS_PROFILE;
}

function aws_profiles() {
  [[ -r "${AWS_CONFIG_FILE:-$HOME/.aws/config}" ]] || return 1
  grep '\[profile' "${AWS_CONFIG_FILE:-$HOME/.aws/config}"|sed -e 's/.*profile \([a-zA-Z0-9_\.-]*\).*/\1/'
}

function aws_check_creds() {
  declare caller_identity;
  caller_identity=($(aws sts get-caller-identity --output text));
  if ! [ "${?}" -eq 0 ]; then
    echo "Error: unable to verify credentials with AWS" >&2;
    return 1;
  fi;
  local account_id="${caller_identity[(w)1]}";
  local arn="${caller_identity[(w)2]}";
  local user_id="${caller_identity[(w)3]}";

  if [[ -n "${account_id}" && -n "${arn}" && -n "${user_id}" ]]; then
    echo "Credentials valid for the following Account/User:"
    echo "AWS Profile: ${AWS_PROFILE}";
    echo "Account ID: ${account_id}";
    echo "ARN: ${arn}";
    echo "User ID: ${user_id}";
    return 0;
  else
    echo "Unhandled error with 'aws sts get-caller-identity'" >&2;
    return 1;
  fi;
}

function aws_set_creds() {
 
  local available_profiles=($(aws_profiles))
  if [[ -z "${available_profiles[(r)$1]}" ]]; then
    echo "${fg[red]}Profile '$1' not found in '${AWS_CONFIG_FILE:-$HOME/.aws/config}'" >&2
    echo "Available profiles: ${(j:, :)available_profiles:-no profiles found}${reset_color}" >&2
    return 1
  fi

  aws_unset_creds;
  if ! [ "${?}" -eq 0 ]; then
    return 1;
  fi;
  
  AWS_PROFILE=$1;
  export AWS_PROFILE
  aws_check_creds;
  if ! [ "${?}" -eq 0 ]; then
    return 1;
  fi;
}

# Authenticate with an MFA Token Code
function aws_auth_mfa() {

  declare -a session_tokens;

  # Check for valid AWS credentials
  # TODO: does not currently check whether current state is an expired STS token
  local caller_identity=($(aws sts get-caller-identity --output text));
  if ! [ "${?}" -eq 0 ]; then
    echo "Error: current AWS credential configuration invalid - did you forget to run aws_set_creds?" >&2;
    return 1;
  fi;

  # Check if currently using an STS token (i.e. MFA, role assumed, or some other funkiness)
  if [[ -n "${AWS_SESSION_TOKEN+x}" ]]; then
    echo "Error: already using an STS token, you probably don't want to do MFA authentication at this point - perhaps run aws_reset_creds to reset" >&2;
    return 1;
  fi;

  # save existing credentials, if present
  [[ -n "${AWS_ACCESS_KEY_ID+x}" ]] && export AWS_PREMFA_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}
  [[ -n "${AWS_SECRET_ACCESS_KEY+x}" ]] && export AWS_PREMFA_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}
  [[ -n "${AWS_SESSION_TOKEN+x}" ]] && export AWS_PREMFA_SESSION_TOKEN=${AWS_SESSION_TOKEN}

  # Get MFA Serial
  #
  # Assumes "iam list-mfa-devices" is permitted without MFA
  local mfa_serial="$(aws iam list-mfa-devices --query 'MFADevices[*].SerialNumber' --output text)";
  if ! [ "${?}" -eq 0 ]; then
    echo "Failed to retrieve MFA serial number" >&2;
    return 1;
  fi;

  # Read the token from the console
  echo -n "MFA Token Code for [${AWS_PROFILE}]: ";
  read -r -s token_code;

  # Call STS to get the session credentials
  #
  # Assumes "sts get-session-token" is permitted without MFA
  session_tokens=($(aws sts get-session-token --token-code "${token_code}" --serial-number "${mfa_serial}" --output text));
  if ! [ "${?}" -eq 0 ]; then
    echo "STS MFA Request Failed" >&2;
    return 1;
  fi;

  # Set the environment credentials as given by STS
  export AWS_ACCESS_KEY_ID="${session_tokens[(w)2]}";
  export AWS_SECRET_ACCESS_KEY="${session_tokens[(w)4]}";
  export AWS_SESSION_TOKEN="${session_tokens[(w)5]}";

  export AWS_MFA_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID}";
  export AWS_MFA_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY}";
  export AWS_MFA_SESSION_TOKEN="${AWS_SESSION_TOKEN}";
  export AWS_MFA_EXPIRY="${session_tokens[(w)3]}";

  if [[ -n "${AWS_ACCESS_KEY_ID}" && -n "${AWS_SECRET_ACCESS_KEY}" && -n "${AWS_SESSION_TOKEN}" ]]; then
    echo "MFA Succeeded. With great power comes great responsibility...";
    #echo -e "\033]6;1;bg;red;brightness;270\a"
    #echo -e "\033]6;1;bg;green;brightness;60\a"
    #echo -e "\033]6;1;bg;blue;brightness;83\a"

    return 0;
  else
    echo "MFA Failed" >&2;
    return 1;
  fi;
}

# Assume an IAM role
function aws_assume_role(){

  declare -a session_tokens;

  if [ "$#" -lt 1 ]; then
    echo "Usage: aws_assume_role <role-name> [<account-id>]" >&2;
    echo " - where <role-name> is the name of a role in the AWS account that you have credentials for" >&2;
    echo " - where <account-id> is optionally the id of the AWS account containing the role" >&2;
    echo "Alternative usage with ARN: aws_assume_role -arn <role-arn>" >&2;
    return 1;
  fi;

  # Check for valid AWS credentials
  # TODO: does not currently check whether current state is an expired STS token
  declare caller_identity;
  caller_identity=($(aws sts get-caller-identity --output text));
  if ! [ "${?}" -eq 0 ]; then
    echo "Error: current AWS credential configuration invalid - did you forget to run aws_set_creds?" >&2;
    return 1;
  fi;

  local current_aws_account_id="${caller_identity[(w)1]}";
  local current_principal_arn="${caller_identity[(w)2]}";
  local current_principal_user_id="${caller_identity[(w)3]}";

  # save existing credentials, if present
  [[ -n "${AWS_ACCESS_KEY_ID+x}" ]] && export AWS_PREASSUME_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}
  [[ -n "${AWS_SECRET_ACCESS_KEY+x}" ]] && export AWS_PREASSUME_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}
  [[ -n "${AWS_SESSION_TOKEN+x}" ]] && export AWS_PREASSUME_SESSION_TOKEN=${AWS_SESSION_TOKEN}

  local role="${1}";
  if [[ -n "${2}" ]]; then
    if [[ "${1}" == "-arn" ]]; then
      local role_arn="${2}";
      local aws_account_id="from-arn";
    else
      local aws_account_id="${2}";
      local role_arn="arn:aws:iam::${aws_account_id}:role/${role}";
    fi;
  else
    local aws_account_id="${current_aws_account_id}"
    local role_arn="arn:aws:iam::${aws_account_id}:role/${role}";
  fi;

  declare current_user;
  current_user="$(echo ${current_principal_arn} | cut -d'/' -f 2)";
  if [[ ${current_principal_user_id:0:4} == "AROA" ]]; then
    # current credentials are for a role so we get the current role name
    current_user="${current_user}-$(echo ${current_principal_user_id} | cut -d':' -f 2)"
  fi;
  if [[ ${aws_account_id} == ${current_aws_account_id} ]]; then
    local session_name="${current_user}";
  else
    local session_name="${current_aws_account_id}-${current_user}";
  fi;

  session_tokens=($(aws sts assume-role \
    --role-arn "${role_arn}" \
    --role-session-name "${session_name}" \
    --query Credentials \
    --output text; ));

  if ! [ "${?}" -eq 0 ]; then
    echo "STS Assume Role Request Failed" >&2;
    return 1;
  fi;

  # Set the environment credentials as given by STS
  export AWS_ACCESS_KEY_ID="${session_tokens[(w)1]}";
  export AWS_SECRET_ACCESS_KEY="${session_tokens[(w)3]}";
  export AWS_SESSION_TOKEN="${session_tokens[(w)4]}";
  export AWS_SESSION_EXPIRY="${session_tokens[(w)2]}";

  export AWS_ASSUMED_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID}";
  export AWS_ASSUMED_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY}";
  export AWS_ASSUMED_SESSION_TOKEN="${AWS_SESSION_TOKEN}";

  if [[ \
       -n "${AWS_ACCESS_KEY_ID}"     \
    && -n "${AWS_SECRET_ACCESS_KEY}" \
    && -n "${AWS_SESSION_TOKEN}"     \
  ]]; then
    export AWS_ROLE="$(echo ${role_arn} | cut -d'/' -f 2)";
    export AWS_ROLE_ARN="${role_arn}";
    echo "Succeessfully assumed the role with ARN ${role_arn}. With great power comes great responsibility...";
    return 0;
  else
    echo "STS Assume Role Failed" >&2;
    return 1;
  fi;
}

# AWS prompt
function prompt_aws_prompt_info() {
  local aws_profile="${AWS_PROFILE:-$AWS_DEFAULT_PROFILE}"

  if [[ -n "$aws_profile" ]]; then
    if [[ -n "$AWS_MFA_EXPIRY" ]]; then  
      local expiry_ts=`date -j -f "%Y-%m-%dT%H:%M:%SZ" $AWS_MFA_EXPIRY +"%s"`
      local now_ts=`date -j +"%s"`
      if [[ now_ts -ge expiry_ts ]]; then
        p10k segment -f 204 -t "${aws_profile} (expired MFA)" -i AWS_ICON -r 
      else
	      p10k segment -f 3 -t "${aws_profile} (active MFA)" -i AWS_ICON -r 
      fi;
    else
      p10k segment -f 3 -t ${aws_profile} -i AWS_ICON -r 
    fi;
  fi
}
