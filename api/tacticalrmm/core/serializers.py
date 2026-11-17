from django.conf import settings
from rest_framework import serializers

from tacticalrmm.constants import (
    ALL_TIMEZONES,
    TerminalShellChoices,
)

from .models import (
    CodeSignToken,
    CoreSettings,
    CustomField,
    GlobalKVStore,
    MonthlyType,
    Schedule,
    ScheduleType,
    URLAction,
)

# credentials stored in CoreSettings; returned only to users who may edit them
CORE_SECRET_FIELDS = (
    "mesh_token",
    "smtp_host_password",
    "twilio_auth_token",
    "open_ai_token",
)
SECRET_MASK = "********"


def mask_core_secrets(data: dict) -> dict:
    for field in CORE_SECRET_FIELDS:
        if data.get(field):
            data[field] = SECRET_MASK
    return data


class HostedCoreMixin:
    def to_representation(self, instance):
        ret = super().to_representation(instance)  # type: ignore
        if getattr(settings, "HOSTED", False):
            for field in ("mesh_site", "mesh_token", "mesh_username"):
                ret[field] = "n/a"

            ret["sync_mesh_with_trmm"] = True
            ret["enable_server_scripts"] = False
            ret["enable_server_webterminal"] = False

        return ret


class CoreSettingsSerializer(HostedCoreMixin, serializers.ModelSerializer):
    all_timezones = serializers.SerializerMethodField("all_time_zones")

    def all_time_zones(self, obj):
        return ALL_TIMEZONES

    def to_representation(self, instance):
        from tacticalrmm.permissions import _has_perm

        ret = super().to_representation(instance)
        request = self.context.get("request")
        # read-only core settings access must not leak the Mesh login key etc.
        if request is None or not _has_perm(request, "can_edit_core_settings"):
            mask_core_secrets(ret)
        return ret

    def validate(self, attrs):
        instance = getattr(self, "instance", None)

        def get_value(key):
            if key in attrs:
                return attrs[key]
            if instance:
                return getattr(instance, key)
            return None

        def require_custom(selection_key, custom_key):
            selection = get_value(selection_key)
            custom_path = (get_value(custom_key) or "").strip()

            if selection == TerminalShellChoices.CUSTOM and not custom_path:
                raise serializers.ValidationError(
                    {custom_key: "Custom shell path is required."}
                )

        require_custom("default_shell_windows", "default_shell_windows_custom")
        require_custom("default_shell_linux", "default_shell_linux_custom")
        require_custom("default_shell_darwin", "default_shell_darwin_custom")

        return attrs

    class Meta:
        model = CoreSettings
        fields = "__all__"


# for audting; secrets never go into the audit log
class CoreSerializer(HostedCoreMixin, serializers.ModelSerializer):
    def to_representation(self, instance):
        return mask_core_secrets(super().to_representation(instance))

    class Meta:
        model = CoreSettings
        fields = "__all__"


class CustomFieldSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomField
        fields = "__all__"


class CodeSignTokenSerializer(serializers.ModelSerializer):
    class Meta:
        model = CodeSignToken
        fields = "__all__"


class KeyStoreSerializer(serializers.ModelSerializer):
    class Meta:
        model = GlobalKVStore
        fields = "__all__"


class URLActionSerializer(serializers.ModelSerializer):
    class Meta:
        model = URLAction
        fields = "__all__"


class ScheduleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Schedule
        fields = "__all__"

    def to_representation(self, instance):
        # we only need to show data for the schedule type, so this function strips out irrelevant fields
        # could have also done this on the frontend instead of here, but this is a bit cleaner
        ret = super().to_representation(instance)

        # need empty states so frontend doesn't break
        empty_states = {
            "run_time_weekdays": [],
            "monthly_months_of_year": [],
            "monthly_days_of_month": [],
            "monthly_weeks_of_month": [],
        }

        if instance.schedule_type == ScheduleType.DAILY:
            fields_to_clear = [
                "run_time_weekdays",
                "monthly_months_of_year",
                "monthly_days_of_month",
                "monthly_weeks_of_month",
            ]
            for field in fields_to_clear:
                ret[field] = empty_states[field]

        elif instance.schedule_type == ScheduleType.WEEKLY:
            fields_to_clear = [
                "monthly_months_of_year",
                "monthly_days_of_month",
                "monthly_weeks_of_month",
            ]
            for field in fields_to_clear:
                ret[field] = empty_states[field]

        elif instance.schedule_type == ScheduleType.MONTHLY:
            if instance.monthly_type == MonthlyType.DAYS:
                fields_to_clear = [
                    "monthly_weeks_of_month",
                    "run_time_weekdays",
                ]
                for field in fields_to_clear:
                    ret[field] = empty_states[field]

            elif instance.monthly_type == MonthlyType.WEEKS:
                fields_to_clear = [
                    "monthly_days_of_month",
                ]
                for field in fields_to_clear:
                    ret[field] = empty_states[field]

        return ret


class ScheduleAuditSerializer(serializers.ModelSerializer):
    class Meta:
        model = Schedule
        fields = "__all__"
