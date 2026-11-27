package app.baluard.mobile.settings

import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import app.baluard.mobile.i18n.t
import app.baluard.mobile.ui.theme.brandFontFamily
import baluard_mobile.shared.generated.resources.Res
import baluard_mobile.shared.generated.resources.fellowship_knights
import org.jetbrains.compose.resources.painterResource

@Composable
fun FellowshipSheet(
    shown: Boolean,
    onDismiss: () -> Unit,
) {
    if (!shown) return
    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(
                t("fellowship.sheet.title"),
                fontFamily = brandFontFamily(),
                textAlign = TextAlign.Center,
                modifier = Modifier.fillMaxWidth(),
            )
        },
        text = {
            Column(modifier = Modifier.fillMaxWidth()) {
                Image(
                    painter = painterResource(Res.drawable.fellowship_knights),
                    contentDescription = null,
                    contentScale = ContentScale.FillWidth,
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(14.dp)),
                )
                Spacer(Modifier.height(12.dp))
                Text(
                    t("fellowship.sheet.thanks"),
                    style = MaterialTheme.typography.bodyMedium,
                    textAlign = TextAlign.Justify,
                )
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) { Text(t("common.close")) }
        },
    )
}
