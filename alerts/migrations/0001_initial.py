from django.db import migrations, models

class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='IngestState',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('path', models.CharField(max_length=1024, unique=True)),
                ('inode', models.PositiveBigIntegerField(blank=True, null=True)),
                ('offset', models.PositiveBigIntegerField(default=0)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.CreateModel(
            name='Alert',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('wazuh_id', models.CharField(max_length=64, unique=True)),
                ('timestamp', models.DateTimeField(help_text='UTC')),
                ('agent_name', models.CharField(blank=True, max_length=128)),
                ('rule_id', models.CharField(blank=True, max_length=32)),
                ('rule_level', models.PositiveSmallIntegerField(blank=True, null=True)),
                ('rule_description', models.TextField(blank=True)),
                ('src_ip', models.CharField(blank=True, max_length=64, null=True)),
                ('full_log', models.TextField(blank=True)),
                ('raw', models.JSONField(default=dict)),
                ('status', models.CharField(choices=[('new', 'New'), ('investigating', 'Investigating'), ('closed', 'Closed'), ('false_positive', 'False positive')], default='new', max_length=16)),
                ('is_demo', models.BooleanField(default=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
            options={
                'ordering': ['-timestamp', '-pk'],
                'indexes': [models.Index(fields=['-timestamp'], name='alert_timestamp_idx'), models.Index(fields=['rule_id'], name='alert_rule_id_idx'), models.Index(fields=['agent_name'], name='alert_agent_idx'), models.Index(fields=['src_ip'], name='alert_src_ip_idx'), models.Index(fields=['status'], name='alert_status_idx'), models.Index(fields=['is_demo'], name='alert_is_demo_idx')],
            },
        ),
    ]
